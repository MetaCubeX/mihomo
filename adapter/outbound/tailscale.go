//go:build !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/tailscale/envknob"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/tsnet"
	D "github.com/miekg/dns"
)

type Tailscale struct {
	*Base
	server      *tsnet.Server
	dnsResolver *dns.Resolver
	option      TailscaleOption
	ctx         context.Context
	cancel      context.CancelFunc
	startOnce   sync.Once
	startErr    error

	backendInitOnce sync.Once
	backendInitCh   chan struct{}
	backendInitErr  error

	startHook             io.Closer
	unregisterDNSResolver func()
}

type TailscaleOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Hostname   string `proxy:"hostname,omitempty"`
	AuthKey    string `proxy:"auth-key,omitempty"`
	ControlURL string `proxy:"control-url,omitempty"`
	StateDir   string `proxy:"state-dir,omitempty"`
	Ephemeral  bool   `proxy:"ephemeral,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`

	AcceptRoutes           *bool  `proxy:"accept-routes,omitempty"`
	ExitNode               string `proxy:"exit-node,omitempty"`
	ExitNodeAllowLANAccess *bool  `proxy:"exit-node-allow-lan-access,omitempty"`
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	envknob.SetNoLogsNoSupport()
	if _, err := buildTailscaleMaskedPrefs(option); err != nil {
		return nil, err
	}
	if option.StateDir == "" {
		option.StateDir = "tailscale"
	}
	option.StateDir = C.Path.Resolve(option.StateDir)
	if !C.Path.IsSafePath(option.StateDir) {
		return nil, C.Path.ErrNotSafePath(option.StateDir)
	}

	addr := option.ControlURL
	if addr == "" {
		addr = "tailscale"
	}
	ctx, cancel := context.WithCancel(context.Background())
	outbound := &Tailscale{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Tailscale,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:        option,
		ctx:           ctx,
		cancel:        cancel,
		backendInitCh: make(chan struct{}),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.server = &tsnet.Server{
		Dir:                  option.StateDir,
		Hostname:             option.Hostname,
		AuthKey:              option.AuthKey,
		ControlURL:           option.ControlURL,
		Ephemeral:            option.Ephemeral,
		SystemDialer:         outbound.dialer.DialContext,
		SystemPacketListener: tailscalePacketListener{dialer: outbound.dialer},
		ExtraRootCAs:         ca.GetCertPool(),
		LookupHook:           tailscaleLookupHook,
		UserLogf: func(format string, args ...any) {
			log.Infoln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
		Logf: func(format string, args ...any) {
			log.Debugln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
	}
	dnsTransport := tailscaleDNSTransport{tailscale: outbound}
	outbound.dnsResolver = dns.NewResolverFromClient(dnsTransport)
	outbound.unregisterDNSResolver = dns.RegisterTailscaleDnsClient(option.Name, dnsTransport)
	outbound.startHook = tunnel.RegisterOnRunning(outbound.startOnRunning)
	return outbound, nil
}

func (t *Tailscale) startOnRunning() {
	if err := t.start(); err != nil {
		log.Warnln("[Tailscale](%s) start failed: %v", t.Name(), err)
	}
}

func (t *Tailscale) start() error {
	t.startOnce.Do(func() {
		if err := t.server.Start(); err != nil {
			t.startErr = err
			t.setBackendInitialized(err)
			return
		}
		ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
		defer cancel()
		if err := t.applyPrefs(ctx); err != nil {
			t.startErr = err
			t.setBackendInitialized(err)
			return
		}
		go t.watchBackendState()
	})
	return t.startErr
}

func (t *Tailscale) ensureStarted(ctx context.Context) error {
	if err := t.start(); err != nil {
		return err
	}
	return t.waitBackendInitialized(ctx)
}

func (t *Tailscale) watchBackendState() {
	lc, err := t.server.LocalClient()
	if err != nil {
		t.setBackendInitialized(err)
		return
	}
	watcher, err := lc.WatchIPNBus(t.ctx, ipn.NotifyInitialState)
	if err != nil {
		t.setBackendInitialized(err)
		return
	}
	defer watcher.Close()

	backendInitialized := false
	exitNodeNeedsStatus := tailscaleExitNodeNeedsStatus(t.option)
	for {
		n, err := watcher.Next()
		if err != nil {
			t.setBackendInitialized(err)
			return
		}
		if n.State == nil {
			continue
		}

		if *n.State != ipn.NoState && !backendInitialized {
			t.setBackendInitialized(nil)
			backendInitialized = true
			if !exitNodeNeedsStatus {
				return
			}
		}
		if exitNodeNeedsStatus && *n.State == ipn.Running {
			if err := t.applyExitNodePrefs(t.ctx); err != nil {
				log.Warnln("[Tailscale](%s) set exit node failed: %v", t.Name(), err)
			}
			return
		}
	}
}

func (t *Tailscale) setBackendInitialized(err error) {
	t.backendInitOnce.Do(func() {
		t.backendInitErr = err
		close(t.backendInitCh)
	})
}

func (t *Tailscale) waitBackendInitialized(ctx context.Context) error {
	select {
	case <-t.backendInitCh:
		return t.backendInitErr
	case <-ctx.Done():
		return ctx.Err()
	case <-t.ctx.Done():
		return t.ctx.Err()
	}
}

func (t *Tailscale) applyPrefs(ctx context.Context) error {
	mp, err := buildTailscaleMaskedPrefs(t.option)
	if err != nil {
		return err
	}
	if mp == nil {
		return nil
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func (t *Tailscale) applyExitNodePrefs(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	mp := &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
	}
	if t.option.ExitNodeAllowLANAccess != nil {
		mp.ExitNodeAllowLANAccess = *t.option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
	}
	if err = mp.SetExitNodeIP(t.option.ExitNode, status); err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func buildTailscaleMaskedPrefs(option TailscaleOption) (*ipn.MaskedPrefs, error) {
	var mp ipn.MaskedPrefs
	changed := false

	if option.AcceptRoutes != nil {
		mp.RouteAll = *option.AcceptRoutes
		mp.RouteAllSet = true
		changed = true
	}
	if option.ExitNode != "" {
		if autoExitNode, ok := ipn.ParseAutoExitNodeString(option.ExitNode); ok {
			mp.AutoExitNode = autoExitNode
			mp.AutoExitNodeSet = true
			changed = true
		}
	}
	if option.ExitNodeAllowLANAccess != nil && !tailscaleExitNodeNeedsStatus(option) {
		mp.ExitNodeAllowLANAccess = *option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
		changed = true
	}
	if !changed {
		return nil, nil
	}
	return &mp, nil
}

func tailscaleExitNodeNeedsStatus(option TailscaleOption) bool {
	if option.ExitNode == "" {
		return false
	}
	_, ok := ipn.ParseAutoExitNodeString(option.ExitNode)
	return !ok
}

func tailscaleLookupHook(ctx context.Context, host string) ([]netip.Addr, error) {
	return resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
}

func (t *Tailscale) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	address := metadata.RemoteAddress()
	if err = t.checkTailscaleRoute(ctx, "tcp", address); err != nil {
		return nil, err
	}
	conn, err := t.server.Dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, t), nil
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if !t.option.UDP {
		return nil, C.ErrNotSupport
	}
	if err = t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	address := metadata.AddrPort().String()
	if err = t.checkTailscaleRoute(ctx, "udp", address); err != nil {
		return nil, err
	}
	conn, err := t.server.Dial(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("packet conn is nil")
	}
	rAddr := metadata.UDPAddr()
	if rAddr == nil {
		return nil, errors.New("packet destination is invalid")
	}
	return newPacketConn(N.NewThreadSafePacketConn(&tailscaleConnPacketConn{Conn: conn, rAddr: rAddr}), t), nil
}

func (t *Tailscale) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if !metadata.Resolved() && metadata.Host != "" {
		ip, err := t.resolveIPWithTransport(ctx, metadata.Host)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (t *Tailscale) checkTailscaleRoute(ctx context.Context, network, address string) error {
	ipp, viaTailscale, err := t.server.DialPlan(ctx, network, address)
	if err != nil {
		return err
	}
	if !viaTailscale {
		return fmt.Errorf("destination %s is not routed by Tailscale; configure exit-node or accept an advertised subnet route", ipp)
	}
	return nil
}

func (t *Tailscale) resolveIPWithTransport(ctx context.Context, host string) (netip.Addr, error) {
	switch t.option.IPVersion {
	case C.IPv4Only:
		return resolver.ResolveIPv4WithResolver(ctx, host, t.dnsResolver)
	case C.IPv6Only:
		return resolver.ResolveIPv6WithResolver(ctx, host, t.dnsResolver)
	case C.IPv6Prefer:
		return resolver.ResolveIPPrefer6WithResolver(ctx, host, t.dnsResolver)
	default:
		return resolver.ResolveIPWithResolver(ctx, host, t.dnsResolver)
	}
}

type tailscaleDNSTransport struct {
	tailscale *Tailscale
}

func (t tailscaleDNSTransport) Address() string {
	return "tailscale://" + t.tailscale.Name()
}

func (t tailscaleDNSTransport) ResetConnection() {}

func (t tailscaleDNSTransport) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	if err := t.tailscale.ensureStarted(ctx); err != nil {
		return nil, err
	}
	q := msg.Question[0]
	qtypeName, ok := D.TypeToString[q.Qtype]
	if !ok {
		return nil, fmt.Errorf("unsupported query type: %d", q.Qtype)
	}
	lc, err := t.tailscale.server.LocalClient()
	if err != nil {
		return nil, err
	}
	response, _, err := lc.QueryDNS(ctx, q.Name, qtypeName)
	if err != nil {
		return nil, err
	}
	var responseMsg D.Msg
	if err = responseMsg.Unpack(response); err != nil {
		return nil, err
	}
	responseMsg.Id = msg.Id
	return &responseMsg, nil
}

func (t *Tailscale) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

func (t *Tailscale) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (t *Tailscale) Close() error {
	t.cancel()
	if t.startHook != nil {
		_ = t.startHook.Close()
	}
	if t.unregisterDNSResolver != nil {
		t.unregisterDNSResolver()
	}
	if t.server != nil {
		return t.server.Close()
	}
	return nil
}

type tailscaleConnPacketConn struct {
	net.Conn
	rAddr net.Addr
}

type tailscalePacketListener struct {
	dialer C.Dialer
}

func (l tailscalePacketListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return l.dialer.ListenPacket(ctx, network, address, netip.AddrPort{})
}

func (c *tailscaleConnPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(b)
	return n, c.rAddr, err
}

func (c *tailscaleConnPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Conn.Write(b)
}

func (c *tailscaleConnPacketConn) LocalAddr() net.Addr {
	if addr := c.Conn.LocalAddr(); addr != nil {
		return addr
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *tailscaleConnPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *tailscaleConnPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *tailscaleConnPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
