//go:build with_gvisor && !no_tailscale

package provider

import (
	"context"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type fakeTailscaleSource struct {
	routes []netip.Prefix
	ch     chan struct{}
}

func (f *fakeTailscaleSource) RouteSet(ctx context.Context) ([]netip.Prefix, error) {
	return f.routes, nil
}

func (f *fakeTailscaleSource) WatchRouteSet(ctx context.Context) <-chan struct{} {
	return f.ch
}

func newTestTailscaleProvider(src P.TailscaleRouteSource) *tailscaleRuleProvider {
	ctx, cancel := context.WithCancel(context.Background())
	strategy := NewIPCidrStrategy()
	strategy.Reset()
	tp := &tailscaleRuleProvider{
		baseProvider: baseProvider{
			behavior: P.IPCIDR,
			strategy: strategy,
		},
		name:      "tailnet",
		proxyName: "ts",
		source:    src,
		updateAt:  time.Now(),
		ctx:       ctx,
		stop:      cancel,
	}
	return tp
}

func TestTailscaleRuleProviderRefreshAndMatch(t *testing.T) {
	src := &fakeTailscaleSource{
		routes: []netip.Prefix{
			netip.MustParsePrefix("100.69.209.53/32"),
			netip.MustParsePrefix("192.168.2.0/24"),
		},
		ch: make(chan struct{}),
	}
	tp := newTestTailscaleProvider(src)
	defer tp.stop()

	if err := tp.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tp.Count() != 2 {
		t.Fatalf("expected 2 routes, got %d", tp.Count())
	}

	// peer address and advertised subnet must match
	for _, ip := range []string{"100.69.209.53", "192.168.2.5"} {
		md := &C.Metadata{DstIP: netip.MustParseAddr(ip)}
		if !tp.Match(md, C.RuleMatchHelper{}) {
			t.Fatalf("expected match for %s", ip)
		}
	}
	// non-tailnet CGNAT must NOT match (the whole point vs a 100.64/10 blanket)
	md := &C.Metadata{DstIP: netip.MustParseAddr("100.64.99.99")}
	if tp.Match(md, C.RuleMatchHelper{}) {
		t.Fatal("unexpected match for non-tailnet CGNAT address")
	}

	// dynamic update: route changes must be reflected after a refresh
	src.routes = append(src.routes, netip.MustParsePrefix("10.42.0.0/16"))
	if err := tp.refresh(); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if tp.Count() != 3 {
		t.Fatalf("expected 3 routes after update, got %d", tp.Count())
	}
	md = &C.Metadata{DstIP: netip.MustParseAddr("10.42.3.14")}
	if !tp.Match(md, C.RuleMatchHelper{}) {
		t.Fatal("expected match for newly advertised subnet")
	}
}

func TestTailscaleRuleProviderMagicDNS(t *testing.T) {
	src := &fakeTailscaleSource{
		routes: []netip.Prefix{netip.MustParsePrefix("100.100.100.100/32")},
		ch:     make(chan struct{}),
	}
	tp := newTestTailscaleProvider(src)
	defer tp.stop()

	if err := tp.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	md := &C.Metadata{DstIP: netip.MustParseAddr("100.100.100.100")}
	if !tp.Match(md, C.RuleMatchHelper{}) {
		t.Fatal("expected match for MagicDNS resolver")
	}
}
