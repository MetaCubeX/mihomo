package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
)

// TargetFallback never changes routes after forwarding application bytes.
type TargetFallbackOption struct {
	AllowLoopbackParent bool   `group:"allow-loopback-parent,omitempty"`
	DirectTimeout       int    `group:"direct-timeout,omitempty"`
	ProxyTimeout        int    `group:"proxy-timeout,omitempty"`
	CacheTTL            int    `group:"cache-ttl,omitempty"`
	DirectCacheTTL      int    `group:"direct-cache-ttl,omitempty"`
	Cooldown            int    `group:"cooldown,omitempty"`
	MaxEntries          int    `group:"max-entries,omitempty"`
	DirectAddressLimit  int    `group:"direct-address-limit,omitempty"`
	MonitorNetwork      *bool  `group:"monitor-network,omitempty"`
	NetworkEpoch        string `group:"network-epoch,omitempty"`
}
type targetRoute struct {
	proxy         bool
	until         time.Time
	failed        error
	pending       chan struct{}
	successes     uint64
	probeSuccess  uint64
	previousProxy bool
}
type TargetFallback struct {
	*GroupBase
	option         TargetFallbackOption
	mu             sync.Mutex
	entries        map[string]*targetRoute
	scope          string
	closed         bool
	monitorEnabled bool
	monitorOnce    sync.Once
	monitor        tun.NetworkUpdateMonitor
	monitorErr     error
	// Kept local to this group: DNS and network observation cannot alter other rules.
	lookup func(context.Context, string) ([]netip.Addr, error)
}

var errProtectedTarget = errors.New("protected target is DIRECT only")
var errTargetClosed = errors.New("target-fallback group closed")

func terminal(err error) error                             { return fmt.Errorf("%w: %w", C.ErrTargetFallbackTerminal, err) }
func (f *TargetFallback) Now() string                      { return "per-target TCP connect" }
func (f *TargetFallback) SupportUDP() bool                 { return false }
func (f *TargetFallback) IsL3Protocol(*C.Metadata) bool    { return false }
func (f *TargetFallback) Unwrap(*C.Metadata, bool) C.Proxy { return nil }
func (f *TargetFallback) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	return nil, terminal(C.ErrNotSupport)
}
func (f *TargetFallback) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, p := range f.GetProxies(false) {
		all = append(all, p.Name())
	}
	return json.Marshal(map[string]any{"type": "TargetFallback", "now": f.Now(), "all": all, "udp": false})
}
func protectedTarget(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip))
}
func protectedHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h != "" && (!strings.Contains(h, ".") || h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local"))
}
func parentLeaf(p C.Proxy, m *C.Metadata) (C.Proxy, error) {
	for depth := 0; depth < 16; depth++ {
		next := p.Unwrap(m, false)
		if next == nil {
			if p.Type() != C.Http && p.Type() != C.Socks5 {
				return nil, errors.New("parent must select an eager HTTP or SOCKS5 adapter")
			}
			addr, e := netip.ParseAddrPort(p.Addr())
			if e != nil || !addr.IsValid() {
				return nil, errors.New("parent server must be a literal IP")
			}
			if p.Type() == C.Socks5 {
				if _, ok := p.Adapter().(outbound.ConfirmedDialer); !ok {
					return nil, errors.New("SOCKS parent cannot confirm CONNECT")
				}
			}
			if p.ProxyInfo().SMUX {
				return nil, errors.New("multiplexed parent is unsupported")
			}
			if p.ProxyInfo().DialerProxy != "" {
				return nil, errors.New("nested dialer-proxy is unsupported")
			}
			return p, nil
		}
		p = next
	}
	return nil, errors.New("parent group cycle")
}

// Local mixed ports may acknowledge CONNECT before any target dial. Require
// explicit opt-in rather than silently treating that as target success.
func (f *TargetFallback) checkedParent(p C.Proxy, m *C.Metadata) (C.Proxy, error) {
	p, err := parentLeaf(p, m)
	if err != nil {
		return nil, err
	}
	addr, _ := netip.ParseAddrPort(p.Addr())
	if !f.option.AllowLoopbackParent && (addr.Addr().IsLoopback() || addr.Addr().IsUnspecified()) {
		return nil, errors.New("loopback parent requires explicit acknowledgement of target CONNECT semantics")
	}
	return p, nil
}

func (f *TargetFallback) startMonitor() error {
	if !f.monitorEnabled {
		return nil
	}
	f.monitorOnce.Do(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.closed {
			f.monitorErr = errTargetClosed
			return
		}
		m, err := tun.NewNetworkUpdateMonitor(log.SingLogger)
		if err != nil {
			f.monitorErr = err
			return
		}
		m.RegisterCallback(f.FlushRouteCache)
		if err = m.Start(); err != nil {
			_ = m.Close()
			f.monitorErr = err
			return
		}
		f.monitor = m
	})
	return f.monitorErr
}

// Only route decisions are shared. Each caller retains its own connection and cancellation.
func (f *TargetFallback) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, terminal(err)
	}
	if err := f.startMonitor(); err != nil {
		return nil, terminal(err)
	}
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return nil, terminal(errTargetClosed)
	}
	m := metadata.Clone()
	ps := f.GetProxies(true)
	if len(ps) != 2 {
		return nil, terminal(errors.New("target-fallback needs exactly two members"))
	}
	if protectedTarget(m.DstIP) || protectedHost(m.Host) {
		c, e := f.direct(ctx, ps[0], m)
		if e != nil {
			return nil, terminal(e)
		}
		c.AppendToChains(f)
		return c, nil
	}
	parent, err := f.checkedParent(ps[1], m)
	if err != nil {
		// A dynamic selector may change after validation. It must not break a
		// healthy DIRECT connection merely because its parent is unsupported.
		f.FlushRouteCache()
		c, directErr := f.direct(ctx, ps[0], m)
		if directErr != nil {
			return nil, terminal(errors.Join(directErr, err))
		}
		c.AppendToChains(f)
		return c, nil
	}
	scope := fmt.Sprint(f.option.NetworkEpoch, "|", parent.Name(), "|", parent.Addr(), "|", parent.ProxyInfo(), "|", dialer.DefaultInterface.Load(), "|", dialer.DefaultRoutingMark.Load())
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, terminal(errTargetClosed)
	}
	if f.scope != scope {
		f.entries = make(map[string]*targetRoute)
		f.scope = scope
	}
	f.mu.Unlock()
	host := strings.ToLower(strings.TrimSuffix(m.Host, "."))
	if host == "" {
		host = m.DstIP.Unmap().String()
	}
	key := fmt.Sprint(host, "|", m.DstPort)
	triedDirect, triedProxy := false, false
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return nil, terminal(err)
		}
		if triedDirect && triedProxy {
			return nil, terminal(lastErr)
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return nil, terminal(errTargetClosed)
		}
		if f.scope != scope {
			f.mu.Unlock()
			return nil, terminal(errors.New("parent policy changed during route decision"))
		}
		e := f.entries[key]
		now := time.Now()
		if e != nil && e.pending != nil {
			done := e.pending
			f.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, terminal(ctx.Err())
			}
		}
		if e != nil && now.Before(e.until) {
			viaProxy, failed := e.proxy, e.failed
			if failed != nil {
				f.mu.Unlock()
				return nil, terminal(failed)
			}
			if (viaProxy && triedProxy) || (!viaProxy && triedDirect) {
				// One cached-route failure elects a leader to try only the untried route.
				e.pending = make(chan struct{})
				e.probeSuccess = e.successes
				e.previousProxy = e.proxy
				f.mu.Unlock()
				return f.probe(ctx, key, e, ps[0], parent, m, !triedDirect, !triedProxy)
			}
			f.mu.Unlock()
			var c C.Conn
			var err error
			if viaProxy {
				triedProxy = true
				c, err = f.parent(ctx, parent, m)
			} else {
				triedDirect = true
				c, err = f.direct(ctx, ps[0], m)
			}
			if err == nil {
				f.mu.Lock()
				if f.entries[key] == e {
					e.successes++
				}
				f.mu.Unlock()
				c.AppendToChains(f)
				return c, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				return nil, terminal(ctx.Err())
			}
			if errors.Is(err, errProtectedTarget) {
				return nil, terminal(err)
			}
			continue
		}
		if triedDirect && triedProxy {
			f.mu.Unlock()
			return nil, terminal(lastErr)
		}
		if e == nil && len(f.entries) >= f.option.MaxEntries {
			victim := ""
			var oldest time.Time
			for k, v := range f.entries {
				if v.pending == nil && (victim == "" || v.until.Before(oldest)) {
					victim = k
					oldest = v.until
				}
			}
			if victim == "" {
				f.mu.Unlock()
				return nil, terminal(errors.New("target-fallback cache busy"))
			}
			delete(f.entries, victim)
		}
		e = &targetRoute{pending: make(chan struct{})}
		f.entries[key] = e
		f.mu.Unlock()
		return f.probe(ctx, key, e, ps[0], parent, m, !triedDirect, !triedProxy)
	}
}
func (f *TargetFallback) probe(ctx context.Context, key string, e *targetRoute, direct, parent C.Proxy, m *C.Metadata, tryDirect, tryProxy bool) (C.Conn, error) {
	var c C.Conn
	var err error
	viaProxy := false
	if tryDirect {
		c, err = f.direct(ctx, direct, m)
	}
	if (err != nil || !tryDirect) && tryProxy && ctx.Err() == nil && !errors.Is(err, errProtectedTarget) {
		viaProxy = true
		c, err = f.parent(ctx, parent, m)
	}
	f.mu.Lock()
	// A caller's cancellation never becomes target-wide cooldown. Wake waiters
	// to elect a new leader, including when a network event invalidated the entry.
	if ctx.Err() != nil || errors.Is(err, errProtectedTarget) {
		if f.entries[key] == e {
			delete(f.entries, key)
		}
	} else {
		if err != nil && e.successes > e.probeSuccess {
			e.proxy = e.previousProxy
			e.failed = nil
			ttl := f.option.CacheTTL
			if !e.proxy {
				ttl = f.option.DirectCacheTTL
			}
			e.until = time.Now().Add(time.Duration(ttl) * time.Millisecond)
		} else {
			e.proxy = viaProxy
			e.failed = err
			ttl := f.option.CacheTTL
			if err != nil {
				ttl = f.option.Cooldown
			} else if !viaProxy {
				ttl = f.option.DirectCacheTTL
			}
			e.until = time.Now().Add(time.Duration(ttl) * time.Millisecond)
		}
	}
	done := e.pending
	e.pending = nil
	if done != nil {
		close(done)
	}
	f.mu.Unlock()
	if ctx.Err() != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, terminal(ctx.Err())
	}
	if err != nil {
		return nil, terminal(err)
	}
	c.AppendToChains(f)
	return c, nil
}
func (f *TargetFallback) parent(ctx context.Context, p C.Proxy, m *C.Metadata) (C.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(f.option.ProxyTimeout)*time.Millisecond)
	defer cancel()
	if p.Type() == C.Socks5 {
		return p.Adapter().(outbound.ConfirmedDialer).DialContextConfirmed(ctx, m.Clone())
	}
	return p.DialContext(ctx, m.Clone())
}
func (f *TargetFallback) direct(ctx context.Context, p C.Proxy, m *C.Metadata) (C.Conn, error) {
	// DNS, all permitted addresses and TCP establishment share one deadline.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(f.option.DirectTimeout)*time.Millisecond)
	defer cancel()
	var ips []netip.Addr
	var err error
	if m.DstIP.IsValid() {
		ips = []netip.Addr{m.DstIP.Unmap()}
	} else if m.Host != "" {
		if f.lookup != nil {
			ips, err = f.lookup(ctx, m.Host)
		} else {
			ips, err = resolver.LookupIPWithResolver(ctx, m.Host, resolver.DirectHostResolver)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, resolver.ErrIPNotFound
	}
	unique := make([]netip.Addr, 0, len(ips))
	seen := map[netip.Addr]bool{}
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.IsValid() && !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}
	if len(unique) == 0 {
		return nil, resolver.ErrIPNotFound
	}
	// A local address in a DNS answer must never cause the hostname to escape to a parent.
	protected := protectedHost(m.Host)
	for _, ip := range unique {
		protected = protected || protectedTarget(ip)
	}
	limit := f.option.DirectAddressLimit
	if limit < 1 {
		limit = 1
	}
	if len(unique) > limit {
		unique = unique[:limit]
	}
	type result struct {
		c   C.Conn
		err error
	}
	results := make(chan result, len(unique))
	started, received := 0, 0
	launch := func(ip netip.Addr) {
		started++
		go func() {
			dm := m.Clone()
			dm.Host = ""
			dm.DstIP = ip
			c, e := p.DialContext(ctx, dm)
			results <- result{c, e}
		}()
	}
	// Drain late winners after cancellation so raced successful sockets cannot leak.
	defer func() {
		cancel()
		remaining := started - received
		if remaining > 0 {
			go func() {
				for i := 0; i < remaining; i++ {
					r := <-results
					if r.c != nil {
						_ = r.c.Close()
					}
				}
			}()
		}
	}()
	launch(unique[0])
	next := 1
	var last error
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case r := <-results:
			received++
			if r.err == nil {
				return r.c, nil
			}
			last = r.err
			if next < len(unique) {
				launch(unique[next])
				next++
			} else if received == started {
				if protected {
					return nil, fmt.Errorf("%w: %w", errProtectedTarget, last)
				}
				return nil, last
			}
		case <-timer.C:
			if next < len(unique) {
				launch(unique[next])
				next++
			}
			timer.Reset(150 * time.Millisecond)
		case <-ctx.Done():
			if protected {
				return nil, fmt.Errorf("%w: %w", errProtectedTarget, ctx.Err())
			}
			return nil, ctx.Err()
		}
	}
}
func NewTargetFallback(o GroupCommonOption, opt TargetFallbackOption, empty C.Proxy, providers []P.ProxyProvider) (*TargetFallback, error) {
	if opt.DirectTimeout == 0 {
		opt.DirectTimeout = 800
	}
	if opt.ProxyTimeout == 0 {
		opt.ProxyTimeout = 2000
	}
	if opt.CacheTTL == 0 {
		opt.CacheTTL = 300000
	}
	if opt.DirectCacheTTL == 0 {
		opt.DirectCacheTTL = 1000
	}
	if opt.Cooldown == 0 {
		opt.Cooldown = 5000
	}
	if opt.MaxEntries == 0 {
		opt.MaxEntries = 4096
	}
	if opt.DirectAddressLimit == 0 {
		opt.DirectAddressLimit = 1
	}
	if opt.DirectTimeout < 1 || opt.ProxyTimeout < 1 || opt.CacheTTL < 1 || opt.DirectCacheTTL < 1 || opt.Cooldown < 1 || opt.MaxEntries < 1 || opt.DirectAddressLimit < 1 || opt.DirectAddressLimit > 2 {
		return nil, errors.New("invalid target-fallback timing, capacity or address limit (1..2)")
	}
	if len(o.Proxies) != 2 || len(o.Use) != 0 || o.IncludeAll || o.IncludeAllProxies || o.IncludeAllProviders || o.Filter != "" || o.ExcludeFilter != "" || o.ExcludeType != "" {
		return nil, errors.New("target-fallback needs exactly two explicit members")
	}
	f := &TargetFallback{GroupBase: NewGroupBase(GroupBaseOption{Name: o.Name, Type: C.TargetFallback, Hidden: o.Hidden, Icon: o.Icon, EmptyFallback: empty, Providers: providers}), option: opt, entries: make(map[string]*targetRoute), monitorEnabled: opt.MonitorNetwork == nil || *opt.MonitorNetwork}
	ps := f.GetProxies(false)
	if len(ps) != 2 || ps[0].Type() != C.Direct {
		return nil, errors.New("first target-fallback member must be DIRECT")
	}
	if _, ok := ps[0].Adapter().(*outbound.Direct); !ok {
		return nil, errors.New("invalid DIRECT adapter")
	}
	if _, err := f.checkedParent(ps[1], &C.Metadata{NetWork: C.TCP}); err != nil {
		return nil, err
	}
	return f, nil
}
func (f *TargetFallback) Providers() []P.ProxyProvider { return f.providers }
func (f *TargetFallback) Proxies() []C.Proxy           { return f.GetProxies(false) }
func (f *TargetFallback) FlushRouteCache() {
	f.mu.Lock()
	f.entries = make(map[string]*targetRoute)
	f.mu.Unlock()
}
func (f *TargetFallback) Close() error {
	f.mu.Lock()
	f.closed = true
	f.entries = make(map[string]*targetRoute)
	monitor := f.monitor
	f.mu.Unlock()
	if monitor != nil {
		return monitor.Close()
	}
	return nil
}
func (f *TargetFallback) RouteCacheStats() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := map[string]int{"entries": len(f.entries), "pending": 0, "proxy": 0, "direct": 0, "cooldown": 0, "expired": 0}
	now := time.Now()
	for _, e := range f.entries {
		switch {
		case e.pending != nil:
			result["pending"]++
		case !now.Before(e.until):
			result["expired"]++
		case e.failed != nil:
			result["cooldown"]++
		case e.proxy:
			result["proxy"]++
		default:
			result["direct"]++
		}
	}
	return result
}
