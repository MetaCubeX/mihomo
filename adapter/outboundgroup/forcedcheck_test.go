package outboundgroup

import (
	"context"
	"errors"
	"sync"
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

func newTestGroupBase(tp *testProvider) *GroupBase {
	return NewGroupBase(GroupBaseOption{
		Name:      "group-under-test",
		Type:      C.URLTest,
		Providers: []P.ProxyProvider{tp},
	})
}

// A forced health check must not run again within the cooldown window,
// otherwise every burst of failed dials rescans all provider nodes.
func TestForcedHealthCheckCooldown(t *testing.T) {
	tp := &testProvider{name: "stub-provider"}
	gb := newTestGroupBase(tp)

	if !gb.tryForceHealthCheck(failureRecheckCooldown, gb.healthCheck) {
		t.Fatal("first forced health check should run")
	}
	if gb.tryForceHealthCheck(failureRecheckCooldown, gb.healthCheck) {
		t.Fatal("second forced health check within cooldown should be suppressed")
	}

	if got := tp.healthChecks.Load(); got != 1 {
		t.Fatalf("expected exactly 1 health check within cooldown window, got %d", got)
	}
}

// healthCheck itself must stay unthrottled: it is the "check now" primitive,
// and the cooldown belongs to the forced-trigger path only. Throttling it
// here is what previously made a forced recovery check impossible to run more
// often than the scheduled one.
func TestHealthCheckItselfIsNotThrottled(t *testing.T) {
	tp := &testProvider{name: "stub-provider"}
	gb := newTestGroupBase(tp)

	gb.healthCheck()
	gb.healthCheck()

	if got := tp.healthChecks.Load(); got != 2 {
		t.Fatalf("expected 2 unthrottled health checks, got %d", got)
	}
}

// The cooldown gate is reached concurrently from many dial goroutines once a
// group starts blackholing, so a check-then-set would let several through.
func TestForcedHealthCheckCooldownIsRaceFree(t *testing.T) {
	tp := &testProvider{name: "stub-provider"}
	gb := newTestGroupBase(tp)

	const goroutines = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	var ran stdatomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if gb.tryForceHealthCheck(failureRecheckCooldown, gb.healthCheck) {
				ran.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := ran.Load(); got != 1 {
		t.Fatalf("expected exactly 1 goroutine to pass the cooldown gate, got %d", got)
	}
	if got := tp.healthChecks.Load(); got != 1 {
		t.Fatalf("expected exactly 1 provider health check, got %d", got)
	}
}

// resolvesToReject runs on every member of every dial and must not disturb
// group state. Probing via Unwrap would run a child Fallback's own selection,
// which drops the pin the user set through the API.
func TestResolvesToRejectDoesNotClearChildPin(t *testing.T) {
	reject := adapter.NewProxy(outbound.NewReject())

	deadNode := adapter.NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = deadNode.URLTest(ctx, stubTestURL, nil)

	child, err := NewFallback(
		GroupCommonOption{Name: "child-fallback", URL: stubTestURL},
		FallbackOption{},
		reject,
		[]P.ProxyProvider{&testProvider{name: "members", proxies: []C.Proxy{deadNode}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	child.ForceSet(deadNode.Name())

	if resolvesToReject(adapter.NewProxy(child)) {
		t.Fatal("a group holding a real node does not blackhole traffic")
	}

	if got := child.selected; got != deadNode.Name() {
		t.Fatalf("read-only probe cleared the child's pin: selected = %q", got)
	}
}

// A plain node has nothing to recurse into and must be answered immediately.
func TestResolvesToRejectPlainNodes(t *testing.T) {
	if resolvesToReject(adapter.NewProxy(outbound.NewDirect())) {
		t.Fatal("a plain node does not resolve to REJECT")
	}
	if !resolvesToReject(adapter.NewProxy(outbound.NewReject())) {
		t.Fatal("REJECT must be reported as blackholing")
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

// After a forced check fires, the failure counter must be reset, otherwise
// every further failed dial in the same window re-enters the maxFailedTimes
// branch and re-emits the warning.
func TestOnDialFailedResetsFailedTimesAfterFiring(t *testing.T) {
	tp := &testProvider{name: "stub-provider"}
	gb := newTestGroupBase(tp)
	gb.testTimeout = 60_000 // keep every failure inside the same burst window

	fired := make(chan struct{}, gb.maxFailedTimes*2)
	fn := func() { fired <- struct{}{} }

	for i := 0; i < gb.maxFailedTimes; i++ {
		gb.onDialFailed(C.Shadowsocks, errors.New("dial timeout"), fn)
	}

	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("expected a forced health check after maxFailedTimes failures")
	}

	gb.failedTestMux.Lock()
	got := gb.failedTimes
	gb.failedTestMux.Unlock()

	if got != 0 {
		t.Fatalf("expected failedTimes to be reset after firing, got %d", got)
	}
}

// A url-test group must skip a member that currently blackholes traffic, the
// same way Fallback does - otherwise the two group types disagree about what
// an empty sub-group means.
func TestURLTestSkipsMemberResolvingToReject(t *testing.T) {
	reject := adapter.NewProxy(outbound.NewReject())

	emptyMember := newURLTestMember(t, "empty-member", reject, &testProvider{name: "no-proxies"})
	liveMember := newURLTestMember(t, "live-member", reject, &testProvider{
		name:    "one-proxy",
		proxies: []C.Proxy{adapter.NewProxy(outbound.NewDirect())},
	})

	u, err := NewURLTest(
		GroupCommonOption{Name: "urltest-group", URL: stubTestURL},
		URLTestOption{},
		reject,
		[]P.ProxyProvider{&testProvider{name: "members", proxies: []C.Proxy{emptyMember, liveMember}}},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got := u.Now(); got != "live-member" {
		t.Fatalf("url-test should skip the member resolving to REJECT, now: %s", got)
	}
}

// When the url-test winner turns out to blackhole traffic, the replacement
// must still respect aliveness. Picking merely "the first member that is not
// REJECT" can hand back a dead node while a live one sits further down the
// list - the delay-based main loop cannot catch this because proxies[0] seeds
// `fast` unconditionally and an unmeasured member carries the max delay.
func TestURLTestReplacementForRejectWinnerPrefersAliveMember(t *testing.T) {
	reject := adapter.NewProxy(outbound.NewReject())

	// proxies[0]: empty sub-group -> resolves to REJECT, but still flagged alive
	emptyMember := newURLTestMember(t, "empty-member", reject, &testProvider{name: "no-proxies"})
	// proxies[1]: plain node, not blackholing, but dead
	deadNode := adapter.NewProxy(outbound.NewDirect())
	// proxies[2]: a genuinely usable member, further down the list
	liveMember := newURLTestMember(t, "live-member", reject, &testProvider{
		name:    "one-proxy",
		proxies: []C.Proxy{adapter.NewProxy(outbound.NewDirect())},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = deadNode.URLTest(ctx, stubTestURL, nil)
	if deadNode.AliveForTestUrl(stubTestURL) {
		t.Fatal("precondition failed: node should be flagged dead")
	}

	u, err := NewURLTest(
		GroupCommonOption{Name: "urltest-group", URL: stubTestURL},
		URLTestOption{},
		reject,
		[]P.ProxyProvider{&testProvider{
			name:    "members",
			proxies: []C.Proxy{emptyMember, deadNode, liveMember},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got := u.Now(); got != "live-member" {
		t.Fatalf("url-test picked %q; must prefer the alive member over a dead one", got)
	}
}

// The fallback for "nothing is alive" must prefer a member that would not
// blackhole traffic over the plain proxies[0], even when that member is a
// group whose own empty-fallback is REJECT.
func TestFallbackPrefersNonRejectMemberWhenNothingAlive(t *testing.T) {
	reject := adapter.NewProxy(outbound.NewReject())

	// member 0 is a group with no proxies -> resolves to its REJECT fallback
	emptyMember := newURLTestMember(t, "empty-member", reject, &testProvider{name: "no-proxies"})
	// member 1 is a plain node that is not alive either, but does not blackhole
	deadNode := adapter.NewProxy(outbound.NewDirect())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = deadNode.URLTest(ctx, stubTestURL, nil)
	if deadNode.AliveForTestUrl(stubTestURL) {
		t.Fatal("precondition failed: node should be flagged dead")
	}

	f, err := NewFallback(
		GroupCommonOption{Name: "fallback-group", URL: stubTestURL},
		FallbackOption{},
		reject,
		[]P.ProxyProvider{&testProvider{name: "members", proxies: []C.Proxy{emptyMember, deadNode}}},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got := f.Now(); got != deadNode.Name() {
		t.Fatalf("fallback should prefer the non-blackholing member, now: %s", got)
	}
}

// An empty group still answers dials through its empty-fallback without an
// error (REJECT hands back a nop connection). Nothing in the group forces a
// health check for this: HealthCheck cannot repopulate an empty provider -
// only the provider's own Update can - so the recovery has to come from the
// selection logic above, which skips such a member while it has alternatives.
func TestRejectDialDoesNotError(t *testing.T) {
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

	if got := tp.healthChecks.Load(); got != 0 {
		t.Fatalf("dialing must not trigger a health check, got %d", got)
	}
}
