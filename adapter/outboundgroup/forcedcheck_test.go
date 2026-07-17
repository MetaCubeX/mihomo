package outboundgroup

import (
	"context"
	stdatomic "sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// stubTestURL is never dialed: tests dial through a REJECT stub (nopConn),
// so the URL only serves as the key under which alive state is stored.
// The .invalid TLD is reserved and guaranteed to never resolve.
const stubTestURL = "https://stub.invalid"

type testProvider struct {
	name         string
	proxies      []C.Proxy
	healthChecks stdatomic.Int32
}

func (t *testProvider) Name() string               { return t.name }
func (t *testProvider) VehicleType() P.VehicleType { return P.Compatible }
func (t *testProvider) Type() P.ProviderType       { return P.Proxy }
func (t *testProvider) Initial() error             { return nil }
func (t *testProvider) Update() error              { return nil }
func (t *testProvider) Proxies() []C.Proxy         { return t.proxies }
func (t *testProvider) Count() int                 { return len(t.proxies) }
func (t *testProvider) Touch()                     {}
func (t *testProvider) HealthCheck()               { t.healthChecks.Add(1) }
func (t *testProvider) Version() uint32            { return 0 }
func (t *testProvider) HealthCheckURL() string     { return "" }
func (t *testProvider) RegisterHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
}

func waitForHealthChecks(t *testing.T, tp *testProvider, want int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if tp.healthChecks.Load() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected at least %d health checks, got %d", want, tp.healthChecks.Load())
}

// A failure-triggered health check must not run again within the cooldown
// window, otherwise every burst of failed dials rescans all provider nodes.
func TestForcedHealthCheckCooldown(t *testing.T) {
	tp := &testProvider{name: "stub-provider"}
	gb := NewGroupBase(GroupBaseOption{
		Name:      "group-under-test",
		Type:      C.URLTest,
		Providers: []P.ProxyProvider{tp},
	})

	gb.healthCheck()
	gb.healthCheck()

	if got := tp.healthChecks.Load(); got != 1 {
		t.Fatalf("expected exactly 1 health check within cooldown window, got %d", got)
	}
}

func newURLTestMember(t *testing.T, name string, reject C.Proxy, provider P.ProxyProvider) C.Proxy {
	t.Helper()
	u, err := NewURLTest(
		GroupCommonOption{Name: name, URL: stubTestURL},
		URLTestOption{},
		reject,
		[]P.ProxyProvider{provider},
	)
	if err != nil {
		t.Fatal(err)
	}
	return adapter.NewProxy(u)
}

// A fallback must skip a member group that currently resolves to REJECT
// (an empty group serving its empty-fallback) immediately, without waiting
// for any health check to mark it dead.
func TestFallbackSkipsMemberResolvingToReject(t *testing.T) {
	reject := adapter.NewProxy(outbound.NewReject())

	emptyMember := newURLTestMember(t, "empty-member", reject, &testProvider{name: "no-proxies"})
	liveMember := newURLTestMember(t, "live-member", reject, &testProvider{
		name:    "one-proxy",
		proxies: []C.Proxy{adapter.NewProxy(outbound.NewDirect())},
	})

	f, err := NewFallback(
		GroupCommonOption{Name: "fallback-group", URL: stubTestURL},
		FallbackOption{},
		reject,
		[]P.ProxyProvider{&testProvider{name: "members", proxies: []C.Proxy{emptyMember, liveMember}}},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got := f.Now(); got != "live-member" {
		t.Fatalf("fallback should skip the member resolving to REJECT, now: %s", got)
	}
}

// Even when every member is flagged dead (e.g. checked before providers
// finished loading), a member with real nodes beats one that would
// blackhole traffic via REJECT.
func TestFallbackPrefersStaleDeadMemberOverReject(t *testing.T) {
	reject := adapter.NewProxy(outbound.NewReject())

	emptyMember := newURLTestMember(t, "empty-member", reject, &testProvider{name: "no-proxies"})
	liveMember := newURLTestMember(t, "live-member", reject, &testProvider{
		name:    "one-proxy",
		proxies: []C.Proxy{adapter.NewProxy(outbound.NewDirect())},
	})

	f, err := NewFallback(
		GroupCommonOption{Name: "fallback-group", URL: stubTestURL},
		FallbackOption{},
		reject,
		[]P.ProxyProvider{&testProvider{name: "members", proxies: []C.Proxy{emptyMember, liveMember}}},
	)
	if err != nil {
		t.Fatal(err)
	}

	// mark the live member dead without touching the network:
	// URLTest with an already-cancelled context fails instantly
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = liveMember.URLTest(ctx, stubTestURL, nil)
	if liveMember.AliveForTestUrl(stubTestURL) {
		t.Fatal("precondition failed: live member should be flagged dead")
	}

	if got := f.Now(); got != "live-member" {
		t.Fatalf("fallback should prefer a stale-dead member over REJECT, now: %s", got)
	}
}

// Dialing through an empty fallback group resolved to REJECT "succeeds"
// (nopConn) and never reports a dial error, so the group must proactively
// re-run its health check to notice members that came back to life.
func TestFallbackRejectDialTriggersHealthCheck(t *testing.T) {
	reject := adapter.NewProxy(outbound.NewReject())
	tp := &testProvider{name: "stub-provider"} // no proxies -> group resolves to empty-fallback

	f, err := NewFallback(
		GroupCommonOption{Name: "fallback-group", URL: stubTestURL},
		FallbackOption{},
		reject,
		[]P.ProxyProvider{tp},
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := f.DialContext(ctx, &C.Metadata{})
	if err != nil {
		t.Fatalf("REJECT dial should not error, got %v", err)
	}
	defer conn.Close()

	waitForHealthChecks(t, tp, 1)
}

// Same for url-test groups: an empty group serving REJECT must re-check its
// providers instead of silently swallowing traffic.
func TestURLTestRejectDialTriggersHealthCheck(t *testing.T) {
	reject := adapter.NewProxy(outbound.NewReject())
	tp := &testProvider{name: "stub-provider"} // no proxies -> group resolves to empty-fallback

	u, err := NewURLTest(
		GroupCommonOption{Name: "urltest-group", URL: stubTestURL},
		URLTestOption{},
		reject,
		[]P.ProxyProvider{tp},
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := u.DialContext(ctx, &C.Metadata{})
	if err != nil {
		t.Fatalf("REJECT dial should not error, got %v", err)
	}
	defer conn.Close()

	waitForHealthChecks(t, tp, 1)
}
