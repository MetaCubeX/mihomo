package networkpolicy

import (
	"testing"
)

func resetGlobal(t *testing.T) {
	t.Helper()
	Uninstall()
	t.Cleanup(Uninstall)
}

func TestInstall_FirstTime_PublishesGlobal(t *testing.T) {
	resetGlobal(t)
	if Global() != nil {
		t.Fatal("precondition: Global() should be nil before Install")
	}

	sel := newMockSelector("auto", "hk", []string{"hk"}, GroupPolicy{})
	mgr := Install(nil, []SelectorWithPolicy{sel}, nil)
	if mgr == nil {
		t.Fatal("Install must return a non-nil Manager")
	}
	if Global() != mgr {
		t.Errorf("Global() must match the Install'd Manager")
	}
}

func TestInstall_HotReload_InheritsInMemoryState(t *testing.T) {
	resetGlobal(t)

	// Cold install: PUT so we have ctx + per-group state to inherit.
	sel1 := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr1 := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel1}, nil)
	mgr1.PutContext(makeCtx("office-5g"))

	// User manually switches — now source=manual.
	sel1.Set("hk")
	mgr1.HandleManualSet("auto")

	// Hot reload: new Manager for the same group. Expect migration of
	// source=manual and last_matched=office.
	sel2 := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr2 := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel2}, nil)

	st := mgr2.states["auto"]
	if st.source != SourceManual {
		t.Errorf("hot reload must inherit source=manual; got %q", st.source)
	}
	if st.lastMatched != "office" {
		t.Errorf("hot reload must inherit last_matched=office; got %q", st.lastMatched)
	}
}

func TestInstall_HotReload_InheritsCachedCtx(t *testing.T) {
	resetGlobal(t)

	sel1 := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr1 := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel1}, nil)
	mgr1.PutContext(makeCtxWithTTL("office-5g", 3600))

	sel2 := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr2 := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel2}, nil)

	// ForceReEvaluate should see the inherited ctx and run against it
	// (bypasses unchanged_network because of the hot-reload trigger).
	res := mgr2.ForceReEvaluate()
	if res == nil {
		t.Fatal("hot reload + inherited ctx: ForceReEvaluate must return a result")
	}
	if !res.MatchedNetworkPresent || res.MatchedNetwork != "office" {
		t.Errorf("ForceReEvaluate after inherit should match office; got present=%v value=%q",
			res.MatchedNetworkPresent, res.MatchedNetwork)
	}
}

func TestInstall_HotReload_NewGroupStartsFresh(t *testing.T) {
	resetGlobal(t)

	sel1 := newMockSelector("a", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "hk"},
	})
	mgr1 := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel1}, nil)
	mgr1.PutContext(makeCtx("office-5g"))
	// After Install, sel1's source=auto.

	// Hot reload adds a new group "b".
	sel2 := newMockSelector("a", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "hk"},
	})
	selNew := newMockSelector("b", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "hk"},
	})
	mgr2 := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel2, selNew}, nil)

	stB := mgr2.states["b"]
	if stB == nil {
		t.Fatal("new group b should be initialized")
	}
	// New group starts with source=unknown (branch B init, since no cachefile).
	// Install's ReleaseBarrier sweep then evaluates and advances source.
	// It should have advanced to auto via matched=none or match.
	if stB.source == SourceUnknown {
		t.Errorf("new group's ReleaseBarrier should have advanced source past unknown; got %q", stB.source)
	}
}

func TestInstall_HotReload_DroppedGroupIsDiscarded(t *testing.T) {
	resetGlobal(t)

	sel1 := newMockSelector("a", "hk", []string{"hk"}, GroupPolicy{})
	selDropped := newMockSelector("b", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "hk"},
	})
	mgr1 := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel1, selDropped}, nil)
	_ = mgr1

	// Reload without "b". "b" is silently discarded — no panic, no state.
	sel2 := newMockSelector("a", "hk", []string{"hk"}, GroupPolicy{})
	mgr2 := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel2}, nil)

	if _, ok := mgr2.states["b"]; ok {
		t.Errorf("dropped group must not persist in new Manager state map")
	}
}

func TestInstall_HotReload_MarksCandidateSetDirty(t *testing.T) {
	resetGlobal(t)

	sel1 := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel1}, nil)

	sel2 := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr2 := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel2}, nil)

	if mgr2.atomicCandidateSetDirtyCounter.Load() == 0 {
		t.Errorf("hot reload should mark candidate_set_dirty")
	}
}

func TestInstall_ReleasesBarrier(t *testing.T) {
	resetGlobal(t)

	sel := newMockSelector("auto", "hk", []string{"hk", "DIRECT"}, GroupPolicy{
		Mapping:      map[string]string{"office": "hk"},
		HasDefault:   true,
		DefaultProxy: "DIRECT",
	})
	mgr := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel}, nil)

	// Branch B init would have set pending=true; Install's ReleaseBarrier
	// sweep should have driven the internal matched=<none> eval → default.
	if sel.Now() != "DIRECT" {
		t.Errorf("Install should release barrier and apply default; got %q", sel.Now())
	}
	if mgr.states["auto"].startupEvalPending {
		t.Errorf("pending must clear after Install's barrier release")
	}
}

// Hot reload across store-selected=false: the new Selector's `selected`
// defaults to COMPATIBLE (or wherever NewSelector sets it), and
// patchSelectGroup is skipped. Without migration, source=manual would
// refer to a proxy the new Selector is no longer showing. inheritFrom
// must Set() the old Now() on the new Selector.
func TestInstall_HotReload_MigratesSelectedProxy(t *testing.T) {
	resetGlobal(t)

	sel1 := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel1}, nil)
	// User manually picks us.
	sel1.Set("us")
	Global().HandleManualSet("auto")

	// Hot reload: brand-new Selector instance with the same candidate
	// set but default `selected` = "hk" (what newMockSelector starts
	// with). inheritFrom should migrate selected=us from the old one.
	sel2 := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel2}, nil)

	if sel2.Now() != "us" {
		t.Errorf("hot reload must migrate selected proxy to survive store-selected=false; got %q", sel2.Now())
	}
}

// Old Selector's proxy is no longer a candidate on the new Selector
// (user removed it from proxies:). inheritFrom best-effort leaves the
// new Selector at its default — no panic, no error surfaced to caller.
func TestInstall_HotReload_SelectedMigration_MissingCandidateTolerated(t *testing.T) {
	resetGlobal(t)

	sel1 := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel1}, nil)
	sel1.Set("us")
	Global().HandleManualSet("auto")

	// New Selector without "us" in candidates.
	sel2 := newMockSelector("auto", "hk", []string{"hk", "DIRECT"}, GroupPolicy{
		Mapping: map[string]string{"office": "hk"},
	})
	Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel2}, nil)

	// Selected stays at default; inheritFrom saw "us" not present and
	// skipped the Set.
	if sel2.Now() == "us" {
		t.Errorf("should not migrate to a proxy not in new candidate set")
	}
}

// White-box regression for the stale-TTL-callback generation guard.
// Calling onTTLExpired with a gen older than mgr.ttlGen must NOT wipe
// the cached ctx or any of its atomic companions; without the guard, a
// renewal racing with the old timer's firing would silently clear the
// freshly-stored context. Asserts multiple invariants so a future
// regression that partially clears state (e.g., nils ttlTimer but
// leaves ctx) is still caught.
func TestOnTTLExpired_StaleGenIgnored(t *testing.T) {
	resetGlobal(t)

	sel := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel}, nil)

	mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	mgr.mu.Lock()
	currentGen := mgr.ttlGen
	timerBefore := mgr.ttlTimer
	expiresBefore := mgr.ctxExpiresAt
	fpBefore := mgr.ctxFingerprint
	mgr.mu.Unlock()
	atomicFpBefore := mgr.atomicCtxFingerprint.Load()
	atomicExpiresBefore := mgr.atomicCtxExpiresAtUnix.Load()

	// Fire a stale callback (gen-1). Must be a no-op on every field.
	mgr.onTTLExpired(currentGen - 1)

	if !mgr.atomicHasCtx.Load() {
		t.Errorf("stale onTTLExpired must not clear hasCtx")
	}
	mgr.mu.Lock()
	if mgr.ttlTimer != timerBefore {
		t.Errorf("stale onTTLExpired must not touch ttlTimer")
	}
	if mgr.ctxExpiresAt != expiresBefore {
		t.Errorf("stale onTTLExpired must not touch ctxExpiresAt")
	}
	if mgr.ctxFingerprint != fpBefore {
		t.Errorf("stale onTTLExpired must not touch ctxFingerprint")
	}
	mgr.mu.Unlock()
	if mgr.atomicCtxFingerprint.Load() != atomicFpBefore {
		t.Errorf("stale onTTLExpired must not touch atomicCtxFingerprint")
	}
	if mgr.atomicCtxExpiresAtUnix.Load() != atomicExpiresBefore {
		t.Errorf("stale onTTLExpired must not touch atomicCtxExpiresAtUnix")
	}
}

func TestUninstall_ClearsGlobal(t *testing.T) {
	resetGlobal(t)

	sel := newMockSelector("auto", "hk", []string{"hk"}, GroupPolicy{})
	Install(nil, []SelectorWithPolicy{sel}, nil)
	Uninstall()
	if Global() != nil {
		t.Errorf("Uninstall must clear global")
	}
}

// Uninstall stops any scheduled TTL timer on the outgoing Manager so
// the AfterFunc closure doesn't keep a dead Manager alive until the
// original expiry. White-box: TTL duration doesn't matter — we just
// need PutContext to have installed a timer, then verify Uninstall
// clears the field.
func TestUninstall_StopsTTLTimer(t *testing.T) {
	resetGlobal(t)

	sel := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := Install([]Network{makeNetwork("office", "office-5g")}, []SelectorWithPolicy{sel}, nil)

	ttlVal := 3600
	ctx := makeCtx("office-5g")
	ctx.TTL = &ttlVal
	mgr.PutContext(ctx)
	mgr.mu.Lock()
	timerBefore := mgr.ttlTimer
	mgr.mu.Unlock()
	if timerBefore == nil {
		t.Fatal("precondition: PutContext with TTL must install a timer")
	}

	Uninstall()

	mgr.mu.Lock()
	timerAfter := mgr.ttlTimer
	mgr.mu.Unlock()
	if timerAfter != nil {
		t.Errorf("Uninstall must stop the TTL timer (set to nil)")
	}
}
