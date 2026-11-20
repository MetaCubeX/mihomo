package outboundgroup

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type tfFake struct {
	*outbound.Base
	calls   atomic.Int32
	fail    bool
	pause   time.Duration
	handler func(context.Context, *C.Metadata) (C.Conn, error)
}

func (p *tfFake) DialContext(ctx context.Context, m *C.Metadata) (C.Conn, error) {
	p.calls.Add(1)
	if p.handler != nil {
		return p.handler(ctx, m)
	}
	select {
	case <-time.After(p.pause):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if p.fail {
		return nil, errors.New("injected connection failure")
	}
	a, b := net.Pipe()
	b.Close()
	return outbound.NewConn(a, p), nil
}
func tfTestGroup(t *testing.T, proxyFail bool) (*TargetFallback, *tfFake, *tfFake) {
	t.Helper()
	d := &tfFake{Base: outbound.NewBase(outbound.BaseOption{Name: "DIRECT", Type: C.Direct}), fail: true, pause: 30 * time.Millisecond}
	p := &tfFake{Base: outbound.NewBase(outbound.BaseOption{Name: "Parent", Type: C.Http, Addr: "127.0.0.1:8080"}), fail: proxyFail}
	ps := []C.Proxy{A.NewProxy(d), A.NewProxy(p)}
	hc := provider.NewHealthCheck(ps, "", 0, 0, true, utils.IntRanges[uint16]{})
	pd, err := provider.NewCompatibleProvider("test", ps, hc)
	if err != nil {
		t.Fatal(err)
	}
	f := &TargetFallback{GroupBase: NewGroupBase(GroupBaseOption{Name: "tf", Type: C.TargetFallback, Providers: []P.ProxyProvider{pd}}), option: TargetFallbackOption{AllowLoopbackParent: true, DirectTimeout: 200, ProxyTimeout: 200, CacheTTL: 80, DirectCacheTTL: 100, DirectAddressLimit: 1, Cooldown: 80, MaxEntries: 8}, entries: make(map[string]*targetRoute)}
	return f, d, p
}
func tfMetadata() *C.Metadata {
	return &C.Metadata{Host: "fixture.test", DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 443, NetWork: C.TCP}
}
func TestTargetFallbackMergeAndTTL(t *testing.T) {
	f, d, p := tfTestGroup(t, false)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := f.DialContext(context.Background(), tfMetadata())
			if e != nil {
				t.Error(e)
			} else {
				c.Close()
			}
		}()
	}
	wg.Wait()
	if d.calls.Load() != 1 || p.calls.Load() != 8 {
		t.Fatalf("counts direct=%d parent=%d", d.calls.Load(), p.calls.Load())
	}
	time.Sleep(100 * time.Millisecond)
	if d.calls.Load() != 1 {
		t.Fatal("background redial")
	}
	c, e := f.DialContext(context.Background(), tfMetadata())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if d.calls.Load() != 2 || p.calls.Load() != 9 {
		t.Fatal("expired entry was not re-evaluated")
	}
}
func TestTargetFallbackCooldownPortsAndStableHost(t *testing.T) {
	f, d, p := tfTestGroup(t, true)
	for i := 0; i < 4; i++ {
		_, e := f.DialContext(context.Background(), tfMetadata())
		if !errors.Is(e, C.ErrTargetFallbackTerminal) {
			t.Fatalf("nonterminal %v", e)
		}
	}
	if d.calls.Load() != 1 || p.calls.Load() != 1 {
		t.Fatal("cooldown failed")
	}
	m := tfMetadata()
	m.DstPort = 8443
	f.DialContext(context.Background(), m)
	if d.calls.Load() != 2 || p.calls.Load() != 2 {
		t.Fatal("ports incorrectly share cache")
	}
	m = tfMetadata()
	m.DstIP = netip.MustParseAddr("192.0.2.3")
	f.DialContext(context.Background(), m)
	if d.calls.Load() != 2 || p.calls.Load() != 2 {
		t.Fatal("CDN IP rotation should retain the host route/cooldown")
	}
}
func TestTargetFallbackProtected(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.2", "100.64.0.2", "169.254.0.2", "::1", "fd00::2"} {
		f, d, p := tfTestGroup(t, false)
		m := tfMetadata()
		m.DstIP = netip.MustParseAddr(ip)
		_, e := f.DialContext(context.Background(), m)
		if e == nil || d.calls.Load() != 1 || p.calls.Load() != 0 {
			t.Fatalf("protected route leaked: %s", ip)
		}
	}
}

func TestTargetFallbackHealthyDirectParallel(t *testing.T) {
	f, d, p := tfTestGroup(t, false)
	d.fail = false
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := f.DialContext(context.Background(), tfMetadata())
			if e != nil {
				t.Error(e)
			} else {
				c.Close()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	t.Logf("8 healthy connections: %s (30ms each)", elapsed)
	if elapsed > 150*time.Millisecond || d.calls.Load() != 8 || p.calls.Load() != 0 {
		t.Fatalf("healthy dials serialized: %s", elapsed)
	}
}
func TestTargetFallbackCancelledCallerDoesNotPoison(t *testing.T) {
	f, d, p := tfTestGroup(t, false)
	d.fail = false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := f.DialContext(ctx, tfMetadata()); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if d.calls.Load() != 0 {
		t.Fatal("already-cancelled caller dialled")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := f.DialContext(ctx, tfMetadata()); done <- e }()
	time.Sleep(time.Millisecond)
	c, e := f.DialContext(context.Background(), tfMetadata())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if e = <-done; !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if p.calls.Load() != 0 {
		t.Fatal("cancelled leader caused fallback")
	}
	if f.RouteCacheStats()["cooldown"] != 0 {
		t.Fatal("caller cancellation cached")
	}
}
func TestTargetFallbackDNSAndDialShareBudget(t *testing.T) {
	f, d, p := tfTestGroup(t, false)
	f.option.DirectTimeout = 80
	d.pause = 60 * time.Millisecond
	f.lookup = func(ctx context.Context, _ string) ([]netip.Addr, error) {
		select {
		case <-time.After(60 * time.Millisecond):
			return []netip.Addr{netip.MustParseAddr("192.0.2.2")}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	m := tfMetadata()
	m.DstIP = netip.Addr{}
	start := time.Now()
	c, e := f.DialContext(context.Background(), m)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	elapsed := time.Since(start)
	t.Logf("DNS+TCP timeout with fallback: %s", elapsed)
	if elapsed > 115*time.Millisecond || d.calls.Load() != 1 || p.calls.Load() != 1 {
		t.Fatalf("DNS and TCP budgets added: %s", elapsed)
	}
}
func TestTargetFallbackProxyCacheSkipsDNS(t *testing.T) {
	f, _, _ := tfTestGroup(t, false)
	var lookups atomic.Int32
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("192.0.2.2")}, nil
	}
	m := tfMetadata()
	m.DstIP = netip.Addr{}
	for i := 0; i < 2; i++ {
		c, e := f.DialContext(context.Background(), m)
		if e != nil {
			t.Fatal(e)
		}
		c.Close()
	}
	if lookups.Load() != 1 {
		t.Fatal("proxy cache hit repeated DNS")
	}
}
func TestTargetFallbackCachedProxyRecoversDirect(t *testing.T) {
	f, d, p := tfTestGroup(t, false)
	c, e := f.DialContext(context.Background(), tfMetadata())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	d.fail = false
	p.fail = true
	c, e = f.DialContext(context.Background(), tfMetadata())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if d.calls.Load() != 2 || p.calls.Load() != 2 || f.RouteCacheStats()["cooldown"] != 0 {
		t.Fatal("cached parent failure did not recover DIRECT")
	}
}
func TestTargetFallbackCachedCancellationDoesNotPoison(t *testing.T) {
	f, _, p := tfTestGroup(t, false)
	c, e := f.DialContext(context.Background(), tfMetadata())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	p.pause = 20 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	f.DialContext(ctx, tfMetadata())
	c, e = f.DialContext(context.Background(), tfMetadata())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if f.RouteCacheStats()["cooldown"] != 0 {
		t.Fatal("cancelled cache-hit caller poisoned target")
	}
}
func TestTargetFallbackBoundedMultipleAddresses(t *testing.T) {
	f, d, p := tfTestGroup(t, false)
	f.option.DirectAddressLimit = 2
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4")}, nil
	}
	d.handler = func(ctx context.Context, m *C.Metadata) (C.Conn, error) {
		if m.DstIP.String() == "192.0.2.2" {
			return nil, errors.New("first address refused")
		}
		a, b := net.Pipe()
		b.Close()
		return outbound.NewConn(a, d), nil
	}
	m := tfMetadata()
	m.DstIP = netip.Addr{}
	c, e := f.DialContext(context.Background(), m)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if d.calls.Load() != 2 || p.calls.Load() != 0 {
		t.Fatal("alternative address was not used within budget")
	}
}
func TestTargetFallbackEpochAndFlush(t *testing.T) {
	f, d, _ := tfTestGroup(t, false)
	call := func() {
		c, e := f.DialContext(context.Background(), tfMetadata())
		if e != nil {
			t.Fatal(e)
		}
		c.Close()
	}
	call()
	f.option.NetworkEpoch = "new-network"
	call()
	if d.calls.Load() != 2 {
		t.Fatal("network epoch did not invalidate")
	}
	f.FlushRouteCache()
	call()
	if d.calls.Load() != 3 {
		t.Fatal("flush did not invalidate")
	}
	f.Close()
	if _, e := f.DialContext(context.Background(), tfMetadata()); !errors.Is(e, errTargetClosed) {
		t.Fatal("closed group accepted a dial")
	}
}
func TestTargetFallbackSuccessOutvotesConcurrentFailure(t *testing.T) {
	f, d, p := tfTestGroup(t, false)
	d.pause = 60 * time.Millisecond
	c, e := f.DialContext(context.Background(), tfMetadata())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	f.option.CacheTTL = 1000
	var entered atomic.Int32
	p.handler = func(ctx context.Context, m *C.Metadata) (C.Conn, error) {
		if entered.Add(1) == 1 {
			time.Sleep(5 * time.Millisecond)
			return nil, errors.New("one transient failure")
		}
		time.Sleep(10 * time.Millisecond)
		a, b := net.Pipe()
		b.Close()
		return outbound.NewConn(a, p), nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := f.DialContext(context.Background(), tfMetadata())
			if e == nil {
				c.Close()
			}
		}()
	}
	wg.Wait()
	if f.RouteCacheStats()["cooldown"] != 0 {
		t.Fatal("a concurrent successful route was suppressed")
	}
}

func TestTargetFallbackProtectedDNSAnswerNeverUsesParent(t *testing.T) {
	f, d, p := tfTestGroup(t, false)
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil
	}
	m := tfMetadata()
	m.DstIP = netip.Addr{}
	_, e := f.DialContext(context.Background(), m)
	if e == nil || d.calls.Load() != 1 || p.calls.Load() != 0 {
		t.Fatal("private DNS answer escaped to parent")
	}
}
func TestTargetFallbackRejectsUnconfirmedParentAtConstruction(t *testing.T) {
	direct := A.NewProxy(outbound.NewDirect())
	bad := A.NewProxy(&tfFake{Base: outbound.NewBase(outbound.BaseOption{Name: "bad", Type: C.Shadowsocks, Addr: "192.0.2.2:18090"})})
	ps := []C.Proxy{direct, bad}
	hc := provider.NewHealthCheck(ps, "", 0, 0, true, utils.IntRanges[uint16]{})
	pd, e := provider.NewCompatibleProvider("invalid", ps, hc)
	if e != nil {
		t.Fatal(e)
	}
	_, e = NewTargetFallback(GroupCommonOption{Name: "invalid", Proxies: []string{"DIRECT", "bad"}}, TargetFallbackOption{}, direct, []P.ProxyProvider{pd})
	if e == nil {
		t.Fatal("unsupported parent accepted")
	}
}

func TestTargetFallbackInvalidDynamicParentKeepsHealthyDirect(t *testing.T) {
	f, d, p := tfTestGroup(t, false)
	d.fail = false
	p.Base = outbound.NewBase(outbound.BaseOption{Name: "changed", Type: C.Shadowsocks, Addr: "192.0.2.2:18090"})
	c, e := f.DialContext(context.Background(), tfMetadata())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if d.calls.Load() != 1 || p.calls.Load() != 0 {
		t.Fatal("invalid dynamic parent interfered with DIRECT")
	}
}

func TestTargetFallbackParsedSocksRetainsConfirmedCapability(t *testing.T) {
	p, err := A.ParseProxy(map[string]any{"name": "parsed", "type": "socks5", "server": "192.0.2.2", "port": 18092})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err = parentLeaf(p, tfMetadata()); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Adapter().(outbound.ConfirmedDialer); !ok {
		t.Fatal("lifecycle wrapper lost confirmed-dial capability")
	}
}

func TestTargetFallbackRejectsImplicitLocalGateway(t *testing.T) {
	f, _, p := tfTestGroup(t, false)
	f.option.AllowLoopbackParent = false
	if _, err := f.checkedParent(A.NewProxy(p), tfMetadata()); err == nil {
		t.Fatal("implicit local mixed port accepted as confirmed target")
	}
}
