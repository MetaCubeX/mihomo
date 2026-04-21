package networkpolicy

import (
	"testing"
	"time"
)

// mockSelector is a lightweight selectorWithPolicy implementation for
// driving Manager's state machine directly without a real
// outboundgroup.Selector (which would require wiring up providers, a
// real proxy map, etc.).
type mockSelector struct {
	name       string
	selected   string
	candidates map[string]struct{}
	policy     GroupPolicy
	source     GroupSource
	setHistory []string
}

func newMockSelector(name, initial string, candidates []string, policy GroupPolicy) *mockSelector {
	m := &mockSelector{
		name:       name,
		selected:   initial,
		candidates: make(map[string]struct{}, len(candidates)),
		policy:     policy,
		source: GroupSource{
			StaticProxies: append([]string(nil), candidates...),
		},
	}
	for _, c := range candidates {
		m.candidates[c] = struct{}{}
	}
	return m
}

func (m *mockSelector) Name() string { return m.name }
func (m *mockSelector) Set(name string) error {
	if _, ok := m.candidates[name]; !ok {
		return &notFoundErr{name: name}
	}
	m.selected = name
	m.setHistory = append(m.setHistory, name)
	return nil
}
func (m *mockSelector) Now() string { return m.selected }
func (m *mockSelector) HasProxy(name string) bool {
	_, ok := m.candidates[name]
	return ok
}
func (m *mockSelector) NetworkPolicy() GroupPolicy { return m.policy }
func (m *mockSelector) GroupSource() GroupSource   { return m.source }

type notFoundErr struct{ name string }

func (e *notFoundErr) Error() string { return "proxy not found: " + e.name }

// --- small helpers for building contexts and networks --------------------

func makeNetwork(name, ssid string) Network {
	m, err := ParseMatch(map[string]any{"ssid": ssid})
	if err != nil {
		panic(err)
	}
	return Network{Name: name, Matcher: m}
}

func makeCtx(ssid string) *NetworkContext {
	ctx := &NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{{
			Name:      "wlan0",
			IfaceType: "wifi",
			SSID:      ssid,
		}},
	}
	return ctx
}

func makeCtxWithTTL(ssid string, ttl int) *NetworkContext {
	ctx := makeCtx(ssid)
	ctx.TTL = &ttl
	return ctx
}

// --- Constructor / branch A+B initial state ------------------------------

func TestNewManager_BranchB_NoCache(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)
	st, ok := mgr.states["auto"]
	if !ok {
		t.Fatal("group state not initialized")
	}
	if st.source != SourceUnknown {
		t.Errorf("branch B should start source=unknown; got %q", st.source)
	}
	if !st.startupEvalPending {
		t.Errorf("branch B should start startupEvalPending=true")
	}
	if st.lastMatchedPresent {
		t.Errorf("branch B should start lastMatched absent")
	}
}

// --- Reason coverage: matched / already_selected / default / etc. --------

func TestPutContext_Matched_SwitchesTarget(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	res, err := mgr.PutContext(makeCtx("office-5g"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Applied) != 1 {
		t.Fatalf("want 1 applied, got %d", len(res.Applied))
	}
	ap := res.Applied[0]
	if ap.Reason != ReasonMatched {
		t.Errorf("want reason=matched, got %q", ap.Reason)
	}
	if !ap.Changed {
		t.Errorf("want changed=true (hk → us)")
	}
	if ap.AppliedProxy != "us" {
		t.Errorf("want applied=us, got %q", ap.AppliedProxy)
	}
	if ap.SelectionSource != SourceAuto {
		t.Errorf("want source=auto after matched; got %q", ap.SelectionSource)
	}
}

func TestPutContext_AlreadySelected_NoChange(t *testing.T) {
	sel := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	res, _ := mgr.PutContext(makeCtx("office-5g"))
	ap := res.Applied[0]
	if ap.Reason != ReasonAlreadySelected {
		t.Errorf("want already_selected, got %q", ap.Reason)
	}
	if ap.Changed {
		t.Errorf("want changed=false; target equals current selection")
	}
	if len(sel.setHistory) != 0 {
		t.Errorf("want no Set() calls; got %v", sel.setHistory)
	}
}

func TestPutContext_Default_NoMappingForNetwork(t *testing.T) {
	sel := newMockSelector("auto", "us", []string{"hk", "DIRECT"}, GroupPolicy{
		Mapping:      map[string]string{"office": "hk"},
		HasDefault:   true,
		DefaultProxy: "DIRECT",
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	// Ctx with a different SSID: matched=<none>, default proxy applies.
	res, _ := mgr.PutContext(makeCtx("home-wifi"))
	ap := res.Applied[0]
	if ap.Reason != ReasonDefault {
		t.Errorf("want default, got %q", ap.Reason)
	}
	if ap.AppliedProxy != "DIRECT" {
		t.Errorf("want applied=DIRECT, got %q", ap.AppliedProxy)
	}
}

func TestPutContext_NoChangeNoDefault(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "hk"}, // no default
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	// matched=<none>, no default → no_change_no_default; keep current.
	res, _ := mgr.PutContext(makeCtx("home-wifi"))
	ap := res.Applied[0]
	if ap.Reason != ReasonNoChangeNoDefault {
		t.Errorf("want no_change_no_default, got %q", ap.Reason)
	}
	if ap.AppliedProxy != "hk" {
		t.Errorf("want unchanged applied=hk, got %q", ap.AppliedProxy)
	}
	st := mgr.states["auto"]
	if st.source != SourceAuto {
		t.Errorf("want source=auto after no_change_no_default, got %q", st.source)
	}
}

func TestPutContext_MissingTarget_NoStateAdvance(t *testing.T) {
	// Policy target "subscription-node" is not in StaticProxies and
	// HasProxy returns false → missing_target; state stays.
	sel := newMockSelector("auto", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "subscription-node"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	res, _ := mgr.PutContext(makeCtx("office-5g"))
	ap := res.Applied[0]
	if ap.Reason != ReasonMissingTarget {
		t.Errorf("want missing_target, got %q", ap.Reason)
	}
	st := mgr.states["auto"]
	if st.source != SourceUnknown {
		t.Errorf("source must stay unknown after missing_target; got %q", st.source)
	}
	if st.lastMatchedPresent {
		t.Errorf("last_matched must not advance on missing_target")
	}
}

// --- Manual-wins semantics ------------------------------------------------

func TestHandleManualSet_PreservesLastMatched(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	// First evaluate to set source=auto + lastMatched=office.
	mgr.PutContext(makeCtx("office-5g"))
	// User manually picks.
	sel.Set("hk")
	mgr.HandleManualSet("auto")

	st := mgr.states["auto"]
	if st.source != SourceManual {
		t.Errorf("want source=manual, got %q", st.source)
	}
	if st.lastMatched != "office" {
		t.Errorf("last_matched must not move on manual set; got %q", st.lastMatched)
	}
}

func TestPutContext_ManualLocked_SameMatched(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	mgr.PutContext(makeCtx("office-5g"))
	sel.Set("hk")
	mgr.HandleManualSet("auto")

	// Same network again → manual_locked; Set not called.
	sel.setHistory = nil
	res, _ := mgr.PutContext(makeCtx("office-5g"))
	ap := res.Applied[0]
	if ap.Reason != ReasonManualLocked {
		t.Errorf("want manual_locked, got %q", ap.Reason)
	}
	if ap.AppliedProxy != "hk" {
		t.Errorf("want hk preserved, got %q", ap.AppliedProxy)
	}
	if len(sel.setHistory) != 0 {
		t.Errorf("manual_locked must not call Set(); got %v", sel.setHistory)
	}
}

func TestPutContext_ManualTakenOverOnNetworkChange(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us", "DIRECT"}, GroupPolicy{
		Mapping: map[string]string{"office": "us", "home": "DIRECT"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{
		makeNetwork("office", "office-5g"),
		makeNetwork("home", "home-wifi"),
	}, nil)

	mgr.PutContext(makeCtx("office-5g"))
	sel.Set("hk")
	mgr.HandleManualSet("auto")

	// Network changes to home → auto takes over, switches to DIRECT.
	res, _ := mgr.PutContext(makeCtx("home-wifi"))
	ap := res.Applied[0]
	if ap.Reason != ReasonMatched {
		t.Errorf("want matched (auto takeover), got %q", ap.Reason)
	}
	if ap.AppliedProxy != "DIRECT" {
		t.Errorf("want DIRECT, got %q", ap.AppliedProxy)
	}
	st := mgr.states["auto"]
	if st.source != SourceAuto {
		t.Errorf("source must flip to auto on network change; got %q", st.source)
	}
}

// --- unchanged_network --------------------------------------------------

func TestPutContext_UnchangedNetwork_SameMatchedAutoSource(t *testing.T) {
	sel := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	mgr.PutContext(makeCtx("office-5g")) // source→auto, lastMatched=office
	sel.setHistory = nil
	res, _ := mgr.PutContext(makeCtx("office-5g"))
	ap := res.Applied[0]
	if ap.Reason != ReasonUnchangedNetwork {
		t.Errorf("want unchanged_network, got %q", ap.Reason)
	}
	if len(sel.setHistory) != 0 {
		t.Errorf("unchanged must not Set()")
	}
}

// --- DELETE / TTL preserve state -----------------------------------------

func TestDeleteContext_PreservesState(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	mgr.PutContext(makeCtx("office-5g"))
	sel.Set("hk")
	mgr.HandleManualSet("auto")

	mgr.DeleteContext()

	st := mgr.states["auto"]
	if st.source != SourceManual {
		t.Errorf("DELETE must preserve source=manual; got %q", st.source)
	}
	if st.lastMatched != "office" {
		t.Errorf("DELETE must preserve last_matched; got %q", st.lastMatched)
	}
	if sel.Now() != "hk" {
		t.Errorf("DELETE must preserve selected proxy; got %q", sel.Now())
	}
	if mgr.ctx != nil {
		t.Errorf("DELETE must clear cached ctx")
	}
}

// --- TTL light path ------------------------------------------------------

func TestTTLLightPath_SameFingerprintBothTTL_ShortCircuits(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	// First PUT with TTL: full evaluation, caches expires_at, switches hk→us.
	first, _ := mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	if first.Applied[0].Reason != ReasonMatched {
		t.Fatalf("first PUT should match, got %v", first.Applied[0].Reason)
	}
	firstExpires := *first.ExpiresAt

	// Second PUT with same ctx + TTL: should go through light path.
	time.Sleep(10 * time.Millisecond) // ensure expires_at advances
	sel.setHistory = nil
	second, _ := mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	if len(sel.setHistory) != 0 {
		t.Errorf("light path must not Set(); got %v", sel.setHistory)
	}
	ap := second.Applied[0]
	if ap.Reason != ReasonUnchangedNetwork {
		t.Errorf("light path should report unchanged_network, got %q", ap.Reason)
	}
	if !second.ExpiresAt.After(firstExpires) {
		t.Errorf("expires_at must advance: first=%v second=%v", firstExpires, *second.ExpiresAt)
	}
}

func TestTTLLightPath_StickyToSticky_FallsThrough(t *testing.T) {
	// Both PUTs sticky (no TTL): light path's condition (b) and (c) fail.
	sel := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	mgr.PutContext(makeCtx("office-5g"))
	res, _ := mgr.PutContext(makeCtx("office-5g"))
	// Must go through full evaluation; reason is unchanged_network via
	// the STATE MACHINE path (same matched + source=auto), not light path.
	if res.Applied[0].Reason != ReasonUnchangedNetwork {
		t.Errorf("want unchanged_network, got %q", res.Applied[0].Reason)
	}
	if res.ExpiresAt != nil {
		t.Errorf("sticky ctx must have nil expires_at; got %v", res.ExpiresAt)
	}
}

func TestTTLLightPath_MissingTargetPendingDisables(t *testing.T) {
	// Target "sub-node" not in candidates → missing_target. Next PUT with
	// same ctx must NOT take the light path (condition d fails), so the
	// state machine gets a chance to retry.
	sel := newMockSelector("auto", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "sub-node"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	first, _ := mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	if first.Applied[0].Reason != ReasonMissingTarget {
		t.Fatalf("first should miss target, got %v", first.Applied[0].Reason)
	}

	// Second PUT, same ctx + ttl: condition (d) fails → full evaluation.
	// Add "sub-node" as candidate now so the retry succeeds.
	sel.candidates["sub-node"] = struct{}{}
	sel.source.StaticProxies = append(sel.source.StaticProxies, "sub-node")

	second, _ := mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	if second.Applied[0].Reason != ReasonMatched {
		t.Errorf("retry must actually re-evaluate and match, got %q", second.Applied[0].Reason)
	}
}

func TestTTLLightPath_CandidateSetDirtyDisables(t *testing.T) {
	sel := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	first, _ := mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	_ = first

	// Simulate provider refresh: candidate_set_dirty set.
	mgr.OnCandidateSetDirty()

	sel.setHistory = nil
	second, _ := mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	// Must have gone through full evaluation — verifiable indirectly by
	// checking that OnCandidateSetDirty's flag was cleared after the
	// evaluation.
	if mgr.atomicCandidateSetDirtyCounter.Load() != 0 {
		t.Errorf("candidate_set_dirty counter must clear after a full evaluation (no concurrent bump)")
	}
	// Reason will be unchanged_network (state-machine short-circuit),
	// but the critical invariant is that the full path ran (dirty flag
	// cleared), not that Set was called.
	_ = second
}

// --- Barrier + startup_eval_pending --------------------------------------

func TestReleaseBarrier_NoCtx_EvaluatesAsMatchedNone(t *testing.T) {
	// Branch B, no ctx pushed during barrier. Release should trigger
	// matched=<none> evaluation; policy has default so DIRECT is set.
	sel := newMockSelector("auto", "hk", []string{"hk", "DIRECT"}, GroupPolicy{
		Mapping:      map[string]string{"office": "hk"},
		HasDefault:   true,
		DefaultProxy: "DIRECT",
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	mgr.ReleaseBarrier("auto")

	if sel.Now() != "DIRECT" {
		t.Errorf("barrier release must apply default; got %q", sel.Now())
	}
	st := mgr.states["auto"]
	if st.source != SourceAuto {
		t.Errorf("post-release source must be auto; got %q", st.source)
	}
	if st.lastMatched != MatchedNone {
		t.Errorf("post-release last_matched must be MatchedNone; got %q", st.lastMatched)
	}
	if st.startupEvalPending {
		t.Errorf("startup_eval_pending must clear after successful release")
	}
}

func TestReleaseBarrier_WithCtx_UsesCachedCtx(t *testing.T) {
	// Branch B, barrier period PUT arrived with matched=office but
	// target missing. Release should re-evaluate with cached ctx now
	// that providers are ready.
	sel := newMockSelector("auto", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "sub-node"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	// PUT during barrier — missing_target.
	first, _ := mgr.PutContext(makeCtx("office-5g"))
	if first.Applied[0].Reason != ReasonMissingTarget {
		t.Fatalf("setup: want missing_target, got %v", first.Applied[0].Reason)
	}
	st := mgr.states["auto"]
	if !st.startupEvalPending {
		t.Errorf("missing_target during barrier must keep pending=true")
	}

	// Provider populates "sub-node"; release.
	sel.candidates["sub-node"] = struct{}{}
	sel.source.StaticProxies = append(sel.source.StaticProxies, "sub-node")
	mgr.ReleaseBarrier("auto")

	if sel.Now() != "sub-node" {
		t.Errorf("post-release must retry and set sub-node; got %q", sel.Now())
	}
	if mgr.states["auto"].startupEvalPending {
		t.Errorf("successful retry must clear pending")
	}
}

func TestReleaseBarrier_Idempotent(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "DIRECT"}, GroupPolicy{
		Mapping:      map[string]string{"office": "hk"},
		HasDefault:   true,
		DefaultProxy: "DIRECT",
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	mgr.ReleaseBarrier("auto")
	sel.setHistory = nil
	mgr.ReleaseBarrier("auto")
	if len(sel.setHistory) != 0 {
		t.Errorf("second release must be no-op; got Set history %v", sel.setHistory)
	}
}

// --- ForceReEvaluate (hot reload) ----------------------------------------

func TestForceReEvaluate_NoCtx_NoOp(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	res := mgr.ForceReEvaluate()
	if res != nil {
		t.Errorf("no cached ctx → ForceReEvaluate must return nil")
	}
}

func TestForceReEvaluate_WithCtx_BypassesStability(t *testing.T) {
	// Initially unchanged_network after second PUT; ForceReEvaluate with
	// same ctx should still run the evaluation (simulating a policy-
	// mapping YAML edit).
	sel := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)
	mgr.PutContext(makeCtx("office-5g"))

	// Swap the policy so office → hk instead of us.
	sel.policy = GroupPolicy{Mapping: map[string]string{"office": "hk"}}
	res := mgr.ForceReEvaluate()
	if res == nil {
		t.Fatal("expected result on force re-evaluate with cached ctx")
	}
	if res.Applied[0].Reason != ReasonMatched {
		t.Errorf("want matched on re-evaluation (policy changed), got %q", res.Applied[0].Reason)
	}
	if sel.Now() != "hk" {
		t.Errorf("force re-eval must apply new policy; got %q", sel.Now())
	}
}

// --- Defensive copy -------------------------------------------------------

func TestPutContext_DeepCopy_CallerMutationIsolated(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	ctx := makeCtx("office-5g")
	ctx.Interfaces[0].Subnets = []string{"10.0.0.0/24"}
	_, err := mgr.PutContext(ctx)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	// Mutate caller's slice; manager's cached ctx must not change.
	ctx.Interfaces[0].Subnets[0] = "MUTATED"
	ctx.Interfaces[0].SSID = "MUTATED"
	if mgr.ctx.Interfaces[0].Subnets[0] == "MUTATED" {
		t.Errorf("manager shared caller's Subnets slice")
	}
	if mgr.ctx.Interfaces[0].SSID == "MUTATED" {
		t.Errorf("manager shared caller's SSID string (shouldn't — strings are immutable though)")
	}
}

// --- Persistence writes ---------------------------------------------------

// Manager writes to cachefile only on state change (§5.6.3). Without a
// real cachefile we can only test indirectly by checking that
// persistStateLocked is reachable — covered transitively in the reason
// tests above via the NewManager(..., nil) path where cache is nil and
// writes are skipped without error.

// --- Status ---------------------------------------------------------------

func TestGetStatus_BeforeAnyPut_NoContext(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "hk"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	st := mgr.GetStatus()
	if st.HasContext {
		t.Errorf("fresh manager should report HasContext=false")
	}
	if len(st.Groups) != 1 {
		t.Errorf("want 1 group in status, got %d", len(st.Groups))
	}
	if st.Groups[0].SelectionSource != SourceUnknown {
		t.Errorf("initial source should be unknown, got %q", st.Groups[0].SelectionSource)
	}
}

// Regression: manual set during branch-B barrier must NOT clear
// startup_eval_pending — the post-barrier recheck is still required
// so the auto-takeover rule can reassert if matched has advanced
// (§5.6.2 row 1 only touches selection_source).
func TestHandleManualSet_PreservesStartupEvalPending(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	// Branch B → startupEvalPending starts true.
	if !mgr.states["auto"].startupEvalPending {
		t.Fatal("precondition: branch B must start pending=true")
	}
	mgr.HandleManualSet("auto")
	if !mgr.states["auto"].startupEvalPending {
		t.Errorf("HandleManualSet must not clear startup_eval_pending")
	}
}

// Regression: ReleaseBarrier post-recheck that resolves missing_target
// must clear the global atomicHasPendingMissingTarget so TTL light path
// condition (d) re-enables (§5.6.3).
func TestReleaseBarrier_ClearsGlobalPendingOnResolve(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "sub-node"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	// PUT during barrier — missing_target.
	mgr.PutContext(makeCtx("office-5g"))
	if !mgr.atomicHasPendingMissingTarget.Load() {
		t.Fatal("precondition: missing_target should set atomic flag")
	}

	// Provider populates target; release barrier.
	sel.candidates["sub-node"] = struct{}{}
	sel.source.StaticProxies = append(sel.source.StaticProxies, "sub-node")
	mgr.ReleaseBarrier("auto")

	if mgr.atomicHasPendingMissingTarget.Load() {
		t.Errorf("atomicHasPendingMissingTarget must clear after barrier-release resolves missing_target")
	}
}

// Regression: ForceReEvaluate must consume the candidate_set_dirty
// signal (§5.8.3 hot reload is a full evaluation).
func TestForceReEvaluate_ClearsCandidateSetDirty(t *testing.T) {
	sel := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)
	mgr.PutContext(makeCtx("office-5g"))

	mgr.OnCandidateSetDirty()
	if mgr.atomicCandidateSetDirtyCounter.Load() == 0 {
		t.Fatal("precondition: OnCandidateSetDirty must set counter")
	}
	mgr.ForceReEvaluate()
	if mgr.atomicCandidateSetDirtyCounter.Load() != 0 {
		t.Errorf("ForceReEvaluate must clear candidate_set_dirty")
	}
}

// Regression: matched_network in GetStatus is a CTX-level property,
// NOT a per-group aggregate. A group stuck in missing_target never
// advances last_matched, but the ctx still matches — GetStatus must
// reflect the ctx match.
func TestGetStatus_MatchedFromCtx_NotFromGroupState(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk"}, GroupPolicy{
		Mapping: map[string]string{"office": "sub-node"}, // target unreachable
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	mgr.PutContext(makeCtx("office-5g")) // → missing_target, last_matched stays nil
	if mgr.states["auto"].lastMatchedPresent {
		t.Fatal("precondition: missing_target must leave lastMatched nil")
	}

	st := mgr.GetStatus()
	if !st.MatchedNetworkPresent || st.MatchedNetwork != "office" {
		t.Errorf("matched_network must come from ctx; got present=%v value=%q", st.MatchedNetworkPresent, st.MatchedNetwork)
	}
}

// Regression: missing_target pending bit must be cleared when the ctx
// returns to the original matched via the sameMatched short-circuit.
// Without the fix, once any evaluation hit missing_target, the pending
// bit would stay true even after the user navigated back to a network
// where the original (reachable) target applied — permanently disabling
// TTL light-path condition (d) for the entire process lifetime.
func TestEvaluate_ReturnToOriginalMatched_ClearsPending(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{
			"office": "us",
			"home":   "unreachable", // deliberately not in candidates
		},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{
		makeNetwork("office", "office-5g"),
		makeNetwork("home", "home-wifi"),
	}, nil)

	// PUT(office) → matched, source=auto, pending=false.
	mgr.PutContext(makeCtx("office-5g"))
	if mgr.atomicHasPendingMissingTarget.Load() {
		t.Fatal("precondition: matched path must not set pending")
	}

	// PUT(home) → missing_target (unreachable), pending=true.
	mgr.PutContext(makeCtx("home-wifi"))
	if !mgr.atomicHasPendingMissingTarget.Load() {
		t.Fatal("precondition: missing_target must set pending")
	}

	// PUT(office) again → sameMatched short-circuit must clear pending.
	mgr.PutContext(makeCtx("office-5g"))
	if mgr.atomicHasPendingMissingTarget.Load() {
		t.Errorf("sameMatched short-circuit must clear missingTargetPending; TTL light path stays disabled otherwise")
	}
}

// Regression: TTL light-path heartbeat must refresh ctxReceivedAt so
// GetStatus().AgeSeconds reports "time since last host heartbeat" not
// "time since first PUT". Without the refresh a sticky-heartbeat client
// would see AgeSeconds climb forever.
func TestTTLLightPath_RefreshesReceivedAtForAge(t *testing.T) {
	sel := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	firstStamp := mgr.ctxReceivedAt
	// Sleep long enough that a non-refreshed stamp is clearly detectable
	// even with coarse clock resolution on Windows.
	time.Sleep(30 * time.Millisecond)
	mgr.PutContext(makeCtxWithTTL("office-5g", 3600)) // light-path heartbeat

	if !mgr.ctxReceivedAt.After(firstStamp) {
		t.Errorf("ctxReceivedAt must advance on TTL heartbeat; first=%v second=%v", firstStamp, mgr.ctxReceivedAt)
	}
}

// Regression: TTL light path must report the real matched_network even
// when the config has 0 policy groups. Before the fix, the light path
// reverse-derived matched_network from the first group's lastMatched,
// which defaulted to MatchedNone when no groups existed — so the first
// PUT returned "office" (full path) and the second same-ctx TTL PUT
// returned null (light path).
func TestTTLLightPath_ZeroGroups_MatchedNetworkStable(t *testing.T) {
	mgr := NewManager(nil, []Network{makeNetwork("office", "office-5g")}, nil)

	first, _ := mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	if !first.MatchedNetworkPresent || first.MatchedNetwork != "office" {
		t.Fatalf("first PUT matched_network: present=%v value=%q; want present=true value=office",
			first.MatchedNetworkPresent, first.MatchedNetwork)
	}

	time.Sleep(10 * time.Millisecond)
	second, _ := mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	if !second.MatchedNetworkPresent || second.MatchedNetwork != "office" {
		t.Errorf("light-path PUT matched_network regressed: present=%v value=%q; want present=true value=office",
			second.MatchedNetworkPresent, second.MatchedNetwork)
	}
	if len(second.Applied) != 0 {
		t.Errorf("applied[] must be empty when no policy groups exist; got %v", second.Applied)
	}
}

// Regression: GetStatus populates age_seconds from ctxReceivedAt.
func TestGetStatus_AgeSecondsPopulated(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	mgr.PutContext(makeCtx("office-5g"))
	time.Sleep(10 * time.Millisecond)
	st := mgr.GetStatus()
	if st.AgeSeconds == nil {
		t.Fatal("AgeSeconds must be set after PUT")
	}
	if *st.AgeSeconds < 0 {
		t.Errorf("AgeSeconds must be non-negative, got %d", *st.AgeSeconds)
	}
}

// Regression: a TTL callback that was scheduled against an old ctx
// must not wipe a newer ctx that arrived in between. Tested by
// scheduling a very-short TTL, replacing with a long TTL before the
// old timer fires, then waiting past when the old timer would have
// fired to confirm ctx is still cached.
func TestPutContext_StaleTTLCallbackDoesNotWipeNewCtx(t *testing.T) {
	sel := newMockSelector("auto", "us", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	// First PUT with 1-second TTL.
	mgr.PutContext(makeCtxWithTTL("office-5g", 1))
	// Immediately renew with a longer TTL (simulating heartbeat).
	mgr.PutContext(makeCtxWithTTL("office-5g", 3600))
	// Wait past when the first timer would have fired.
	time.Sleep(1500 * time.Millisecond)

	// The second ctx with the long TTL must still be cached — the
	// stale-fire guard should have dropped the first timer's callback.
	if !mgr.atomicHasCtx.Load() {
		t.Errorf("stale TTL callback wiped fresh ctx (TTL generation guard missing?)")
	}
}

func TestGetStatus_AfterPut_ReflectsState(t *testing.T) {
	sel := newMockSelector("auto", "hk", []string{"hk", "us"}, GroupPolicy{
		Mapping: map[string]string{"office": "us"},
	})
	mgr := NewManager([]selectorWithPolicy{sel}, []Network{makeNetwork("office", "office-5g")}, nil)

	mgr.PutContext(makeCtx("office-5g"))
	st := mgr.GetStatus()
	if !st.HasContext {
		t.Errorf("want HasContext=true after PUT")
	}
	if !st.MatchedNetworkPresent || st.MatchedNetwork != "office" {
		t.Errorf("want matched=office, got present=%v value=%q", st.MatchedNetworkPresent, st.MatchedNetwork)
	}
	if st.Groups[0].CurrentProxy != "us" {
		t.Errorf("want current=us, got %q", st.Groups[0].CurrentProxy)
	}
}
