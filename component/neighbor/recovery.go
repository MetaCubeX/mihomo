package neighbor

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const (
	queryTimeout       = 100 * time.Millisecond
	maxQueryInterfaces = 32
	maxRecoveries      = 16
	maxRecoveryWaiters = 256
	maxSourceWaiters   = 32
	maxCooldowns       = 4096
	recoveryCooldown   = 2 * time.Second
)

type Options struct {
	Probe      bool
	Timeout    time.Duration
	Interfaces []string
}

func DefaultOptions() Options { return Options{Timeout: time.Second} }

func (o Options) Equal(other Options) bool {
	if o.Probe != other.Probe || o.Timeout != other.Timeout || len(o.Interfaces) != len(other.Interfaces) {
		return false
	}
	for i, v := range o.Interfaces {
		if v != other.Interfaces[i] {
			return false
		}
	}
	return true
}
func ValidateTimeout(ms int) error {
	if ms <= 0 || ms > 60000 {
		return fmt.Errorf("src-mac-timeout must be between 1 and 60000 milliseconds")
	}
	return nil
}

type queryBackend interface {
	Get(context.Context, int, netip.Addr) (MAC, bool, error)
	Probe(context.Context, int, netip.Addr) error
	Close() error
}

type recoveryKey struct {
	index int
	ip    netip.Addr
}
type recoveryFlight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	mac     MAC
	ok      bool
}
type recoveryGroup struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	options    Options
	flights    map[recoveryKey]*recoveryFlight
	cooldown   map[recoveryKey]time.Time
	waiters    int
	tokens     float64
	lastToken  time.Time
	lastReport time.Time
	wg         sync.WaitGroup
	closed     bool
}

func (r *Resolver) startRecovery(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	opts := r.options
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	r.recovery = &recoveryGroup{ctx: ctx, cancel: cancel, options: opts, flights: make(map[recoveryKey]*recoveryFlight), cooldown: make(map[recoveryKey]time.Time), tokens: maxRecoveries, lastToken: time.Now()}
	r.mu.Unlock()
}
func (r *Resolver) stopRecovery() {
	r.mu.Lock()
	g := r.recovery
	r.recovery = nil
	r.mu.Unlock()
	if g == nil {
		return
	}
	g.mu.Lock()
	g.closed = true
	g.cancel()
	g.mu.Unlock()
	g.wg.Wait()
}
func (r *Resolver) Configure(options Options) {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	options.Interfaces = append([]string(nil), options.Interfaces...)
	r.mu.Lock()
	old := r.options
	r.options = options
	r.mu.Unlock()
	if !old.Equal(options) && r.cancel != nil {
		r.stopRecovery()
		r.startRecovery(r.ctx)
	}
}
func (r *Resolver) Options() Options {
	r.mu.RLock()
	defer r.mu.RUnlock()
	options := r.options
	options.Interfaces = append([]string(nil), options.Interfaces...)
	return options
}

// Resolve performs at most one shared, bounded recovery after a cache miss.
// A cancelled waiter does not cancel other connections sharing its recovery.
func (r *Resolver) Resolve(ctx context.Context, index int, ip netip.Addr) (MAC, bool) {
	if ctx.Err() != nil {
		return MAC{}, false
	}
	if mac, ok := r.Lookup(index, ip); ok {
		return mac, true
	}
	r.mu.RLock()
	g := r.recovery
	if g == nil || r.table == nil {
		r.mu.RUnlock()
		return MAC{}, false
	}
	key, ok := r.table.key(index, ip)
	ambiguous := ok && key.index == 0 && len(r.table.byIP[key.ip]) > 1
	r.mu.RUnlock()
	if !ok || ambiguous {
		return MAC{}, false
	}
	return g.resolve(ctx, key, func(ctx context.Context) (MAC, bool) { return r.recover(ctx, g, key) })
}

func (g *recoveryGroup) resolve(ctx context.Context, key recoveryKey, work func(context.Context) (MAC, bool)) (MAC, bool) {
	ctx, cancel := context.WithTimeout(ctx, g.options.Timeout)
	defer cancel()
	g.mu.Lock()
	if g.closed || ctx.Err() != nil || g.waiters >= maxRecoveryWaiters {
		g.mu.Unlock()
		return MAC{}, false
	}
	f := g.flights[key]
	if f != nil {
		if f.waiters >= maxSourceWaiters {
			g.mu.Unlock()
			return MAC{}, false
		}
	} else {
		now := time.Now()
		if now.Before(g.lastToken) {
			g.lastToken = now
		} else {
			g.tokens += now.Sub(g.lastToken).Seconds() * maxRecoveries
			if g.tokens > maxRecoveries {
				g.tokens = maxRecoveries
			}
			g.lastToken = now
		}
		if now.Before(g.cooldown[key]) || len(g.flights) >= maxRecoveries || g.tokens < 1 {
			g.mu.Unlock()
			return MAC{}, false
		}
		if len(g.cooldown) >= maxCooldowns {
			for k, until := range g.cooldown {
				if !now.Before(until) {
					delete(g.cooldown, k)
				}
			}
			if len(g.cooldown) >= maxCooldowns {
				g.mu.Unlock()
				return MAC{}, false
			}
		}
		deadline, _ := ctx.Deadline()
		workCtx, stop := context.WithDeadline(g.ctx, deadline)
		f = &recoveryFlight{done: make(chan struct{}), cancel: stop}
		g.tokens--
		g.flights[key] = f
		g.cooldown[key] = now.Add(recoveryCooldown)
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			defer stop()
			mac, ok := work(workCtx)
			g.mu.Lock()
			f.mac, f.ok = mac, ok
			if g.flights[key] == f {
				delete(g.flights, key)
			}
			g.cooldown[key] = time.Now().Add(recoveryCooldown)
			close(f.done)
			g.mu.Unlock()
		}()
	}
	f.waiters++
	g.waiters++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		f.waiters--
		g.waiters--
		if f.waiters == 0 {
			f.cancel()
			if g.flights[key] == f {
				delete(g.flights, key)
			}
		}
		g.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return MAC{}, false
	case <-g.ctx.Done():
		return MAC{}, false
	case <-f.done:
		if ctx.Err() != nil || g.ctx.Err() != nil {
			return MAC{}, false
		}
		return f.mac, f.ok
	}
}

func (t *table) key(index int, ip netip.Addr) (recoveryKey, bool) {
	if !ip.IsValid() {
		return recoveryKey{}, false
	}
	if zone := ip.Zone(); zone != "" {
		z, err := strconv.Atoi(zone)
		if err != nil {
			z = t.names[zone]
		}
		if z <= 0 || (index != 0 && index != z) {
			return recoveryKey{}, false
		}
		index = z
		ip = ip.WithZone("")
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return recoveryKey{}, false
	}
	if index != 0 {
		if _, ok := t.links[index]; !ok {
			return recoveryKey{}, false
		}
	}
	return recoveryKey{index: index, ip: ip}, true
}

// probeInterface selects a single directly connected Ethernet interface. It
// does not infer ingress from a route lookup, or probe via a next-hop gateway.
func (t *table) probeInterface(key recoveryKey, allowed []string) int {
	var allowedMap map[string]struct{}
	if len(allowed) > 0 {
		allowedMap = make(map[string]struct{}, len(allowed))
		for _, name := range allowed {
			allowedMap[name] = struct{}{}
		}
	}
	selected := 0
	for index, addresses := range t.addresses {
		if allowedMap != nil {
			name := t.links[index]
			if _, ok := allowedMap[name]; !ok {
				continue
			}
		}
		for prefix := range addresses {
			if prefix.Bits() == 0 {
				continue
			}
			if prefix.Addr() == key.ip {
				return 0
			} // never solicit our own address
			if !t.probeable[index] || !prefix.Contains(key.ip) || (key.index != 0 && key.index != index) {
				continue
			}
			if key.ip.Is4() && prefix.Bits() < 31 {
				b := key.ip.As4()
				n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
				mask := uint32(1)<<(32-prefix.Bits()) - 1
				if n&mask == mask || n&mask == 0 {
					return 0
				} // subnet broadcast/network
			}
			if selected != 0 && selected != index {
				return 0
			}
			selected = index
		}
	}
	return selected
}

func (r *Resolver) recover(ctx context.Context, g *recoveryGroup, key recoveryKey) (MAC, bool) {
	// All interfaces must be checked when ingress is unknown: a result from just
	// the return-route interface would conceal duplicate addresses.
	r.mu.RLock()
	if r.table == nil || r.recovery != g {
		r.mu.RUnlock()
		return MAC{}, false
	}
	var allowedMap map[string]struct{}
	if len(g.options.Interfaces) > 0 {
		allowedMap = make(map[string]struct{}, len(g.options.Interfaces))
		for _, name := range g.options.Interfaces {
			allowedMap[name] = struct{}{}
		}
	}
	indices := make([]int, 0, len(r.table.links))
	for index, name := range r.table.links {
		if allowedMap != nil {
			if _, ok := allowedMap[name]; !ok {
				continue
			}
		}
		if key.index == 0 || key.index == index {
			indices = append(indices, index)
		}
	}
	rev := r.revision
	r.mu.RUnlock()
	if len(indices) == 0 {
		return MAC{}, false
	}
	open := r.query
	if open == nil {
		open = openQueryBackend
	}
	q, err := open()
	if err != nil {
		r.recoveryError(g, err)
		return MAC{}, false
	}
	defer q.Close()

	var found MAC
	count := 0
	queryFailed := false
	if len(indices) <= maxQueryInterfaces {
		queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
		defer cancel()
		for _, index := range indices {
			mac, ok, err := q.Get(queryCtx, index, key.ip)
			if err != nil {
				if queryCtx.Err() != nil {
					return MAC{}, false
				}
				r.recoveryError(g, err)
				queryFailed = true
				continue
			}
			if ok {
				found = mac
				count++
			}
		}
		cancel()
		if ctx.Err() != nil || count > 1 {
			return MAC{}, false
		}
	}
	r.mu.RLock()
	if r.table == nil || r.recovery != g {
		r.mu.RUnlock()
		return MAC{}, false
	}
	current, known := r.table.lookup(key.index, key.ip)
	if r.revision != rev {
		r.mu.RUnlock()
		return current, known
	}
	if queryFailed {
		r.mu.RUnlock()
		return MAC{}, false
	}
	if count > 0 {
		r.mu.RUnlock()
		return found, count == 1
	} // never write a query reply over newer notifications
	probeIndex := r.table.probeInterface(key, g.options.Interfaces)
	r.mu.RUnlock()
	if !g.options.Probe || probeIndex == 0 {
		return MAC{}, false
	}
	if err := q.Probe(ctx, probeIndex, key.ip); err != nil {
		if ctx.Err() == nil {
			r.recoveryError(g, err)
		}
		return MAC{}, false
	}
	for {
		r.mu.RLock()
		if r.table == nil || r.recovery != g {
			r.mu.RUnlock()
			return MAC{}, false
		}
		mac, ok := r.table.lookup(key.index, key.ip)
		ambiguous := key.index == 0 && len(r.table.byIP[key.ip]) > 1
		changed := r.changed
		eligible := r.table.probeInterface(key, g.options.Interfaces) == probeIndex
		r.mu.RUnlock()
		if ok {
			return mac, true
		}
		if ambiguous || !eligible {
			return MAC{}, false
		}
		select {
		case <-ctx.Done():
			return MAC{}, false
		case <-changed:
		}
	}
}

func (r *Resolver) recoveryError(g *recoveryGroup, err error) {
	g.mu.Lock()
	report := time.Since(g.lastReport) >= 30*time.Second
	if report {
		g.lastReport = time.Now()
	}
	g.mu.Unlock()
	if report && r.report != nil {
		r.report(fmt.Errorf("source MAC recovery: %w", err))
	}
}
