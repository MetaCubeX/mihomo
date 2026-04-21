package networkpolicy

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"
)

// DefaultBarrierTimeout is the per-group provider-ready barrier timeout
// (architecture §5.6.2 "first-load 超时"). Internal constant for now;
// promoted to a YAML field if user feedback warrants.
const DefaultBarrierTimeout = 15 * time.Second

// ApplyResult is one row of applied[] in the PUT /network/context response
// (architecture §5.4.2).
type ApplyResult struct {
	Group           string
	TargetProxy     string // policy decision; empty when no mapping hit
	AppliedProxy    string // currently applied proxy; always non-empty
	Changed         bool   // did this evaluation call selector.Set()?
	SelectionSource string // auto / manual / unknown
	Reason          string // one of the seven ReasonXxx constants
}

// PutResult is the full state-machine response to PutContext. Maps to the
// §5.4.2 JSON body; REST layer handles wire encoding (nil / MatchedNone →
// JSON null for matched_network etc.).
type PutResult struct {
	// MatchedNetworkPresent + MatchedNetwork mirror the PersistedState
	// last_matched_network tri-state encoding:
	//   - MatchedNetworkPresent=false → nil (never evaluated; should only
	//     appear in intermediate diagnostics, never in a PutResult after
	//     a completed evaluation)
	//   - MatchedNetworkPresent=true && MatchedNetwork==MatchedNone →
	//     evaluated, no match
	//   - MatchedNetworkPresent=true && MatchedNetwork=="<name>" → matched
	MatchedNetworkPresent bool
	MatchedNetwork        string

	Applied   []ApplyResult
	ExpiresAt *time.Time // nil = sticky (no TTL)
}

// StatusResult is the GET /network/context response model. Similar to
// PutResult but without the per-group Changed flag (read-only snapshot).
type StatusResult struct {
	HasContext            bool
	Context               *NetworkContext // deep-copied snapshot
	MatchedNetworkPresent bool
	MatchedNetwork        string
	Groups                []GroupStatus
	ExpiresAt             *time.Time
	AgeSeconds            *int64
}

// GroupStatus is one row of groups[] in GET /network/context.
type GroupStatus struct {
	Group                     string
	CurrentProxy              string
	SelectionSource           string
	LastMatchedNetworkPresent bool
	LastMatchedNetwork        string
}

// groupState is the per-group state-machine cell the Manager maintains.
// Access is guarded by Manager.mu (the serial queue).
type groupState struct {
	// source is one of SourceAuto / SourceManual / SourceUnknown.
	source string

	// lastMatched + lastMatchedPresent encode the tri-state described in
	// §5.6.1: "nil" (Present=false), MatchedNone (Present=true, value =
	// MatchedNone), or concrete name (Present=true, value = name).
	lastMatched        string
	lastMatchedPresent bool

	// missingTargetPending records whether the last evaluation for this
	// group ended in reason=missing_target. Used to compute the global
	// atomicHasPendingMissingTarget flag (TTL light path condition d)
	// from any code path that re-evaluates a single group (not just the
	// all-groups sweep in PutContext / ForceReEvaluate).
	missingTargetPending bool

	// startupEvalPending is true until the provider barrier for this
	// group has released AND (if the group landed in missing_target
	// during the barrier) the post-barrier re-evaluation has run.
	// Transitions (§5.6.2 "provider 屏障的实施契约"):
	//   - initialized true in branch B; false in branch A
	//   - barrier-period PUT that lands in matched/already_selected/
	//     default/no_change_no_default → set false
	//   - barrier-period PUT that lands in missing_target → stays true
	//     so the post-release recheck covers the retry
	//   - barrier release with pending=true → re-evaluates with current
	//     cached ctx (or matched=<none> if no ctx), then clears
	//   - hot reload: preserved verbatim for groups that survived rename-
	//     less; new groups start true (treated as branch B for them)
	startupEvalPending bool

	// barrierReleased flips true when the per-group provider barrier
	// either detected all referenced providers populated OR the 15s
	// timeout elapsed. After release, startup-specific paths no longer
	// apply and the state machine runs in steady state.
	barrierReleased bool
}

// selectorWithPolicy interface is defined in policy.go (unexported to the
// package — outboundgroup.Selector satisfies it via duck-typing, and
// intra-package tests can supply mocks without needing the interface to
// be exported).

// Manager is the single state-machine kernel for the network-policy
// feature. It owns:
//   - per-group state (source / last_matched / startup_eval_pending)
//   - cached NetworkContext snapshot + TTL timer
//   - fingerprint and candidate-set-dirty flags for the TTL light path
//   - per-group provider barriers
//
// The architecture (§5.6.3) requires a single serial queue to prevent
// interleaved evaluation from corrupting state under concurrent manual
// PUT / context PUT / TTL expiry / hot reload. Manager uses a plain
// mutex: all state-mutating APIs acquire mu, complete their work, and
// release. Non-mutating read paths (TTL light path) use atomic loads on
// a narrow set of fields published from within mu.
type Manager struct {
	mu sync.Mutex

	// Stable for the lifetime of the Manager. groupsOrder preserves YAML
	// declaration order so applied[] / groups[] output stays deterministic.
	// Hot reload constructs a fresh Manager in M3c's executor wiring and
	// migrates in-memory state; this type intentionally does not expose
	// an in-place Replace to keep the serial-queue invariants simple.
	groups       map[string]selectorWithPolicy
	groupsOrder  []string
	networks     []Network
	cache        *cachefile.CacheFile
	barrierTTL   time.Duration

	// Per-group state; key = group name. Written only under mu.
	states map[string]*groupState

	// ctx is the cached normalized NetworkContext snapshot. Written only
	// under mu. Deep-copied on every PutContext so callers can't mutate
	// internal state by retaining references to arguments.
	ctx             *NetworkContext
	ctxFingerprint  string
	ctxExpiresAt    *time.Time
	ctxReceivedAt   time.Time // when the cached ctx was stored (for GetStatus age_seconds)
	ttlTimer        *time.Timer // AfterFunc pending TTL expiry; nil when sticky
	ttlGen          uint64      // monotonic stamp — onTTLExpired ignores stale callbacks

	// Atomic-published flags for the TTL light path (§5.6.3). Readers
	// outside mu use atomic loads; writers set them under mu. Field
	// inconsistencies are acceptable — the worst case is one extra full
	// evaluation that the state machine's own idempotent short-circuit
	// absorbs.
	//
	// atomicCandidateSetDirtyCounter is an incrementing counter, not a
	// boolean, so we can distinguish "same dirty event we observed pre-
	// evaluation" from "a new dirty event arrived during the evaluation":
	// PutContext snapshots the counter before entering evaluation and
	// uses CompareAndSwap(snapshot, 0) at the end; if a concurrent
	// OnCandidateSetDirty bumped the counter during the evaluation, the
	// CAS fails and the signal is preserved for the next cycle.
	atomicHasCtx                   atomic.Bool
	atomicCtxFingerprint           atomic.Pointer[string]
	atomicCtxExpiresAtUnix         atomic.Int64 // 0 = sticky
	atomicHasPendingMissingTarget  atomic.Bool
	atomicCandidateSetDirtyCounter atomic.Int64
}

// NewManager constructs a fresh Manager for the given groups + networks,
// restoring per-group state from the cachefile bucket per §5.6.2 branch
// A/B split:
//   - branch A: bucketNetworkPolicy exists (store-selected can be either
//     way; NetworkPolicyStateMap returns (map, true)). Every group with
//     a matching entry restores (source, lastMatched); entries that fail
//     Validate or reference groups no longer declared are silently
//     dropped. Groups without an entry start unknown/nil. startupEval
//     Pending=false for all branch-A groups — no post-barrier internal
//     evaluation.
//   - branch B: no bucket (NetworkPolicyStateMap returns (_, false)).
//     Every group starts unknown/nil with startupEvalPending=true, so
//     that the subsequent ReleaseBarrier call runs an internal
//     matched=<none> evaluation (or uses cached ctx if one was PUT
//     during the barrier).
//
// Providers are not polled here; that belongs to M3c (executor wiring).
// ReleaseBarrier(groupName) is the public entry point executors call
// when a group's referenced providers are populated or the 15s timeout
// elapses.
func NewManager(groups []selectorWithPolicy, networks []Network, cache *cachefile.CacheFile) *Manager {
	m := &Manager{
		groups:      make(map[string]selectorWithPolicy, len(groups)),
		groupsOrder: make([]string, 0, len(groups)),
		networks:    networks,
		cache:       cache,
		barrierTTL:  DefaultBarrierTimeout,
		states:      make(map[string]*groupState, len(groups)),
	}
	for _, g := range groups {
		name := g.Name()
		m.groups[name] = g
		m.groupsOrder = append(m.groupsOrder, name)
	}
	m.initStatesFromCache()
	return m
}

// initStatesFromCache populates m.states from the cachefile bucket,
// driving the branch A / B decision. Called from NewManager. On hot
// reload the executor is responsible for migrating in-memory state
// from the previous Manager before constructing a new one; see the
// M3c wiring for the migration protocol (§5.8.3 preservation rules).
// Assumes no external callers hold mu; skips locking.
func (m *Manager) initStatesFromCache() {
	var (
		stateBytes   map[string][]byte
		bucketExists bool
	)
	if m.cache != nil {
		stateBytes, bucketExists = m.cache.NetworkPolicyStateMap()
	}
	branchA := bucketExists
	for _, name := range m.groupsOrder {
		g := m.groups[name]
		if _, ok := m.states[name]; ok {
			// Already initialized (e.g., preserved across hot reload).
			continue
		}
		st := &groupState{
			source:             SourceUnknown,
			startupEvalPending: !branchA,
		}
		if branchA {
			if raw, ok := stateBytes[name]; ok {
				if restored, err := decodePersisted(raw); err == nil {
					st.source = restored.Source
					if restored.LastMatchedPresent {
						st.lastMatchedPresent = true
						st.lastMatched = restored.LastMatched
					}
				} else {
					// Corrupted record: drop it and GC, leaving this
					// group at unknown/nil within branch A (§5.6.2
					// "部分组缺 entry").
					log.Warnln("[NetworkPolicy] discarding corrupt bucket entry for group %q: %v", name, err)
					if m.cache != nil {
						m.cache.DeleteNetworkPolicyState(name)
					}
				}
			}
			// Group has no entry in the bucket → already unknown/nil;
			// first PUT will force full evaluation per §5.6.2 row 2.
			// startupEvalPending stays false: branch A doesn't run the
			// internal matched=<none> evaluation.
		}
		// Omit groups that have no GroupPolicy attached (defensive: only
		// select groups with network-policy should be in the list at
		// all, but it keeps the state map tight).
		if g.NetworkPolicy().IsEmpty() {
			continue
		}
		m.states[name] = st
	}
}

// decodePersisted unwraps the JSON + Validate chain for load-side
// record recovery. Uses the M3a PersistedState schema.
func decodePersisted(raw []byte) (PersistedState, error) {
	var ps PersistedState
	if err := ps.UnmarshalJSON(raw); err != nil {
		return PersistedState{}, err
	}
	if err := ps.Validate(); err != nil {
		return PersistedState{}, err
	}
	return ps, nil
}

// PutContext applies a new NetworkContext from a host PUT and runs the
// full state machine. Returns a PutResult mirroring §5.4.2 applied[].
//
// Concurrency: acquires mu for the full evaluation + cachefile write.
// The TTL light path (non-evaluating heartbeat refresh) short-circuits
// before mu is acquired and is handled inline.
//
// Ownership: raw is deep-copied before being stored as the new cached
// ctx; callers may mutate raw after return without corrupting Manager
// state. raw is also re-normalized via NormalizeAndValidate so that
// derived fields (subnetsParsed, gatewayIPParsed) are valid for the
// matcher evaluation.
func (m *Manager) PutContext(raw *NetworkContext) (*PutResult, error) {
	if raw == nil {
		return nil, fmt.Errorf("PutContext: nil context")
	}

	// Deep-copy BEFORE normalization so we don't re-normalize the
	// caller's slice/pointer fields (architecture §5.6.3).
	ctx := deepCopyContext(raw)
	if err := ctx.NormalizeAndValidate(); err != nil {
		return nil, err
	}
	fp := ctx.Fingerprint()

	// TTL light path (§5.6.3). All five conditions must hold.
	if resp, ok := m.tryTTLLightPath(ctx, fp); ok {
		return resp, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Snapshot the candidate-set dirty counter BEFORE evaluation so we
	// can distinguish "dirty event we are consuming" from "dirty event
	// that arrived while we were evaluating". Cleared at the end via
	// CAS — if someone bumped the counter during evaluation, the CAS
	// fails and the new event is preserved for the next PUT.
	dirtySnapshot := m.atomicCandidateSetDirtyCounter.Load()

	// Expire the previous TTL timer (if any) — we're about to replace
	// the cached ctx and its expiry window.
	m.stopTTLTimerLocked()

	matched, matchedPresent := m.matchLocked(ctx)
	applied := make([]ApplyResult, 0, len(m.groupsOrder))
	for _, name := range m.groupsOrder {
		st, ok := m.states[name]
		if !ok {
			continue
		}
		res := m.evaluateGroupLocked(name, st, matched, matchedPresent, evalTriggerPutContext)
		applied = append(applied, res)
	}

	// Store new ctx snapshot + fingerprint atomically with the evaluation.
	m.ctx = ctx
	m.ctxFingerprint = fp
	m.ctxReceivedAt = time.Now()
	fpCopy := fp
	m.atomicCtxFingerprint.Store(&fpCopy)
	m.atomicHasCtx.Store(true)

	var expiresAt *time.Time
	if ctx.TTL != nil {
		t := time.Now().Add(time.Duration(*ctx.TTL) * time.Second)
		expiresAt = &t
		m.ctxExpiresAt = &t
		m.atomicCtxExpiresAtUnix.Store(t.UnixNano())
		m.startTTLTimerLocked(t)
	} else {
		m.ctxExpiresAt = nil
		m.atomicCtxExpiresAtUnix.Store(0)
	}

	// candidate_set_dirty (§5.6.3) consumed: only clear if the counter is
	// still at the value we observed pre-evaluation. A bump during the
	// evaluation (concurrent OnCandidateSetDirty) fails the CAS and keeps
	// the signal alive for the next PUT — otherwise the race between a
	// provider refresh and the serial queue would swallow the dirty event.
	m.atomicCandidateSetDirtyCounter.CompareAndSwap(dirtySnapshot, 0)
	m.recomputePendingMissingTargetLocked()

	result := &PutResult{
		MatchedNetworkPresent: matchedPresent,
		MatchedNetwork:        matched,
		Applied:               applied,
		ExpiresAt:             expiresAt,
	}
	return result, nil
}

// tryTTLLightPath checks the five conditions of §5.6.3 and, if all hold,
// returns the lightweight response without entering the serial queue.
// Returns (nil, false) for any condition miss — caller falls through to
// the full evaluation.
//
// Condition set:
//
//	(a) incoming ctx fingerprint == cached fingerprint
//	(b) incoming body has ttl (sticky → false)
//	(c) cached ctx also had ttl (sticky → false)
//	(d) no pending missing_target retry from the last evaluation
//	(e) candidate_set_dirty not set since the last evaluation
//
// Reads use atomic loads and tolerate brief inconsistencies (the manager
// queue writes under mu; cross-field tearing between two atomic loads
// just means we may fall back to the full path once).
func (m *Manager) tryTTLLightPath(incoming *NetworkContext, incomingFP string) (*PutResult, bool) {
	if !m.atomicHasCtx.Load() {
		return nil, false
	}
	cached := m.atomicCtxFingerprint.Load()
	if cached == nil || *cached != incomingFP {
		return nil, false
	}
	if incoming.TTL == nil {
		return nil, false // (b)
	}
	cachedExpiresUnix := m.atomicCtxExpiresAtUnix.Load()
	if cachedExpiresUnix == 0 {
		return nil, false // (c) — cached was sticky
	}
	if m.atomicHasPendingMissingTarget.Load() {
		return nil, false // (d)
	}
	if m.atomicCandidateSetDirtyCounter.Load() != 0 {
		return nil, false // (e)
	}

	// All five conditions hold: just rotate expires_at and emit the
	// response from the current state without evaluating. We still hold
	// mu briefly to read per-group states coherently (a light-path read
	// should not race the serial queue mid-update).
	m.mu.Lock()
	defer m.mu.Unlock()

	// Re-check conditions under mu — atomic reads may have been racing
	// with the serial queue. If anything changed, fall back to full eval.
	if m.ctx == nil || m.ctxFingerprint != incomingFP || m.ctxExpiresAt == nil || m.atomicHasPendingMissingTarget.Load() || m.atomicCandidateSetDirtyCounter.Load() != 0 {
		return nil, false
	}

	now := time.Now()
	newExpires := now.Add(time.Duration(*incoming.TTL) * time.Second)
	m.ctxExpiresAt = &newExpires
	m.ctxReceivedAt = now // heartbeat also refreshes the "when did we last hear from host" stamp so GetStatus().AgeSeconds reports time-since-latest-PUT, not time-since-first-PUT
	// Refresh the cached ctx's TTL pointer so GET /network/context
	// echoes the currently-active TTL. The ctx body itself is
	// fingerprint-identical and doesn't need re-copying.
	if m.ctx != nil {
		ttl := *incoming.TTL
		m.ctx.TTL = &ttl
	}
	m.atomicCtxExpiresAtUnix.Store(newExpires.UnixNano())
	m.stopTTLTimerLocked()
	m.startTTLTimerLocked(newExpires)

	// Recompute matched_network from the cached ctx directly. The light
	// path's fingerprint invariant guarantees Match() returns the same
	// result as the prior full evaluation, so re-running it is cheap and
	// produces the same wire value — without depending on any group's
	// lastMatched as a proxy. Same pattern GetStatus uses, required
	// because a config with 0 policy groups has no group state to fall
	// back to and would otherwise report matched_network=null.
	matched, matchedPresent := m.matchLocked(m.ctx)
	resolveTarget := matched
	if matched == MatchedNone {
		resolveTarget = "" // Resolve treats empty as "no match"
	}

	applied := make([]ApplyResult, 0, len(m.groupsOrder))
	for _, name := range m.groupsOrder {
		st, ok := m.states[name]
		if !ok {
			continue
		}
		g := m.groups[name]
		res := ApplyResult{
			Group:           name,
			AppliedProxy:    g.Now(),
			Changed:         false,
			SelectionSource: st.source,
		}
		// Defensive: the light path's condition (d) + branch-B startup
		// having completed guarantee source != unknown. If we see it
		// anyway, fall back to full evaluation to avoid emitting a
		// nonsense reason (§5.6.3 "源=unknown → 不会出现" fallback).
		if st.source == SourceUnknown {
			log.Warnln("[NetworkPolicy] TTL light path saw source=unknown on group %q; falling back to full evaluation", name)
			return nil, false
		}
		target, _ := g.NetworkPolicy().Resolve(resolveTarget)
		res.TargetProxy = target
		if st.source == SourceManual {
			res.Reason = ReasonManualLocked
		} else {
			res.Reason = ReasonUnchangedNetwork
		}
		applied = append(applied, res)
	}

	return &PutResult{
		MatchedNetworkPresent: matchedPresent,
		MatchedNetwork:        matched,
		Applied:               applied,
		ExpiresAt:             &newExpires,
	}, true
}

// matchLocked evaluates the global Match() against the cached networks
// and returns the per-ctx matched_network value in the tri-state encoding
// used by last_matched_network updates (Present=true always after an
// evaluation; value is either a concrete name or MatchedNone).
func (m *Manager) matchLocked(ctx *NetworkContext) (value string, present bool) {
	name, ok := Match(m.networks, ctx)
	if ok {
		return name, true
	}
	return MatchedNone, true
}

// evalTrigger distinguishes which §5.6.2 row we're processing, so the
// state machine can apply the narrow differences correctly.
type evalTrigger int

const (
	// evalTriggerPutContext is a normal host PUT /network/context.
	evalTriggerPutContext evalTrigger = iota
	// evalTriggerHotReload is a post-reload re-evaluation using the
	// cached ctx (§5.8.3). Bypasses the unchanged_network / manual_locked
	// short-circuit so policy-mapping edits take effect even when ctx
	// fingerprint is stable.
	evalTriggerHotReload
	// evalTriggerBarrierRelease is the internal evaluation the barrier
	// release path runs for groups that still have startupEvalPending=true.
	// Uses the cached ctx if present; otherwise forces matched=<none>.
	evalTriggerBarrierRelease
)

// evaluateGroupLocked runs the §5.6.2 state-machine table for one group.
// Returns the ApplyResult for the group and, as side effects, updates the
// per-group state in m.states (and writes cachefile if state changed).
//
// The trigger argument governs two narrow details:
//   - evalTriggerHotReload forces evaluation regardless of matched stability
//     so YAML policy edits take effect even with stable context.
//   - evalTriggerBarrierRelease treats the absence of cached ctx as
//     matched=<none> (§5.6.4 触发源 2).
func (m *Manager) evaluateGroupLocked(name string, st *groupState, matched string, matchedPresent bool, trigger evalTrigger) (res ApplyResult) {
	g := m.groups[name]
	policy := g.NetworkPolicy()
	res = ApplyResult{
		Group:        name,
		AppliedProxy: g.Now(),
	}
	// SelectionSource is recorded POST-transition — named return value +
	// deferred assignment ensures every return site reports the state
	// machine's post-evaluation source (what the caller will see from
	// here on), not the pre-transition source.
	defer func() { res.SelectionSource = st.source }()

	// source=unknown: force full evaluation ignoring stability checks
	// (§5.6.2 row 2). Covers branch-B first PUT and any group that's
	// lost its cached state.
	forceEval := st.source == SourceUnknown || trigger == evalTriggerHotReload

	// matched_result equality uses the tri-state comparison from §5.6.1:
	// nil (Present=false) compares unequal to anything.
	sameMatched := !forceEval && st.lastMatchedPresent && matchedPresent && st.lastMatched == matched

	// Row 3 / 4: matched stable + source=auto|manual → short-circuit.
	// Clearing missingTargetPending here is important: a prior evaluation
	// that landed in missing_target sets the per-group bit, but if the
	// user moves through ctx states that come back to the original
	// matched (A → B misses → A again), the A-evaluation's short-circuit
	// would otherwise leave pending=true forever, permanently disabling
	// the TTL light path condition (d).
	if sameMatched {
		switch st.source {
		case SourceAuto:
			st.missingTargetPending = false
			res.Reason = ReasonUnchangedNetwork
			target, _ := policy.Resolve(currentMatchedForResolve(matched, matchedPresent))
			res.TargetProxy = target
			return res
		case SourceManual:
			st.missingTargetPending = false
			res.Reason = ReasonManualLocked
			target, _ := policy.Resolve(currentMatchedForResolve(matched, matchedPresent))
			res.TargetProxy = target
			return res
		}
	}

	// Full evaluation: resolve target via policy, then classify + apply.
	target, policyReason := policy.Resolve(currentMatchedForResolve(matched, matchedPresent))
	res.TargetProxy = target

	// Target reachability check: if policy decided on a concrete proxy
	// that isn't currently in the group's candidate set (provider not
	// yet populated, etc.), emit missing_target per §5.8.2. source /
	// last_matched stay put so the next PUT retries.
	if target != "" && !g.HasProxy(target) {
		res.Reason = ReasonMissingTarget
		st.missingTargetPending = true
		return res
	}

	switch policyReason {
	case ReasonMatched:
		// target known-reachable. Set if not already, otherwise
		// already_selected.
		if g.Now() == target {
			res.Reason = ReasonAlreadySelected
		} else {
			if err := g.Set(target); err != nil {
				log.Warnln("[NetworkPolicy] group %q Set(%q) failed: %v", name, target, err)
				// Treat as missing_target — failed Set implies the
				// target cannot be applied right now. State stays put.
				res.Reason = ReasonMissingTarget
				st.missingTargetPending = true
				return res
			}
			res.Changed = true
			res.AppliedProxy = target
			res.Reason = ReasonMatched
		}
		m.advanceStateLocked(name, st, matched, matchedPresent, SourceAuto)

	case ReasonDefault:
		// Policy returned the default proxy. Set if different; source=auto;
		// last_matched advances.
		if g.Now() == target {
			res.Reason = ReasonDefault
		} else {
			if err := g.Set(target); err != nil {
				log.Warnln("[NetworkPolicy] group %q default Set(%q) failed: %v", name, target, err)
				res.Reason = ReasonMissingTarget
				st.missingTargetPending = true
				return res
			}
			res.Changed = true
			res.AppliedProxy = target
			res.Reason = ReasonDefault
		}
		m.advanceStateLocked(name, st, matched, matchedPresent, SourceAuto)

	case ReasonNoChangeNoDefault:
		// Policy has no mapping and no default. Keep current selection;
		// source=auto; last_matched still advances.
		res.Reason = ReasonNoChangeNoDefault
		m.advanceStateLocked(name, st, matched, matchedPresent, SourceAuto)

	default:
		// Unreachable — Resolve only returns the three reasons above.
		log.Warnln("[NetworkPolicy] group %q: unexpected policy reason %q", name, policyReason)
		res.Reason = policyReason
	}

	return res
}

// advanceStateLocked updates per-group state after a successful
// evaluation and writes to cachefile iff state changed. Matches §5.6.3
// "Cachefile 写盘条件" — only persist on real transitions to keep
// cachefile churn down.
func (m *Manager) advanceStateLocked(name string, st *groupState, matched string, matchedPresent bool, newSource string) {
	oldSource := st.source
	oldPresent := st.lastMatchedPresent
	oldMatched := st.lastMatched

	st.source = newSource
	if matchedPresent {
		st.lastMatchedPresent = true
		st.lastMatched = matched
	}
	// startup_eval_pending: resolved outcome (non-missing-target) clears
	// the pending flag — the group has a definite answer for the
	// post-barrier recheck (§5.6.2 规则).
	st.startupEvalPending = false
	// Resolved outcome also means no missing_target pending for this group.
	st.missingTargetPending = false

	stateChanged := oldSource != st.source || oldPresent != st.lastMatchedPresent || oldMatched != st.lastMatched
	if !stateChanged {
		return
	}
	m.persistStateLocked(name, st)
}

// recomputePendingMissingTargetLocked scans all groups and republishes
// the global atomicHasPendingMissingTarget flag. Called from any path
// that runs an evaluation — PutContext, ForceReEvaluate, ReleaseBarrier
// — so condition (d) of the TTL light path stays in sync with the
// actual state (§5.6.3 contract).
func (m *Manager) recomputePendingMissingTargetLocked() {
	any := false
	for _, st := range m.states {
		if st.missingTargetPending {
			any = true
			break
		}
	}
	m.atomicHasPendingMissingTarget.Store(any)
}

// persistStateLocked writes the group's current state to the cachefile
// bucket, gated on StoreSelected. No-op on nil cache.
func (m *Manager) persistStateLocked(name string, st *groupState) {
	if m.cache == nil {
		return
	}
	ps := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             st.source,
		LastMatched:        st.lastMatched,
		LastMatchedPresent: st.lastMatchedPresent,
	}
	if err := WriteNetworkPolicyState(m.cache, name, ps); err != nil {
		// Write-side Validate failure is a programmer bug: log and
		// skip. Don't propagate — the runtime already applied the
		// transition; cachefile is best-effort persistence.
		log.Warnln("[NetworkPolicy] group %q: persist failed: %v", name, err)
	}
}

// currentMatchedForResolve adapts the tri-state matched result to the
// single-string Resolve API (empty string ↔ "no match" to Resolve).
func currentMatchedForResolve(matched string, present bool) string {
	if !present || matched == MatchedNone {
		return ""
	}
	return matched
}

// DeleteContext implements DELETE /network/context: clears the cached
// snapshot and cancels the TTL timer, BUT preserves the state machine
// (source / last_matched / currently-selected proxy stay put per §5.4.3).
func (m *Manager) DeleteContext() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stopTTLTimerLocked()
	m.ctx = nil
	m.ctxFingerprint = ""
	m.ctxExpiresAt = nil

	m.atomicHasCtx.Store(false)
	m.atomicCtxFingerprint.Store(nil)
	m.atomicCtxExpiresAtUnix.Store(0)
	// hasPendingMissingTarget and candidateSetDirty are not touched —
	// they reflect facts about the last completed evaluation's state,
	// which persists across DELETE.
}

// HandleManualSet is invoked when the user manually picks a proxy via
// PUT /proxies/:name for a network-policy-governed group. The state
// machine updates source=manual; last_matched stays put per §5.6.2
// row 1. Cachefile is written on change.
//
// If the group has no network-policy attached, HandleManualSet is a
// no-op — the plain selector.Set path already handled it.
func (m *Manager) HandleManualSet(groupName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	st, ok := m.states[groupName]
	if !ok {
		return
	}
	if st.source == SourceManual {
		return // no transition; cachefile already has this state
	}
	st.source = SourceManual
	// last_matched intentionally unchanged (§5.6.2 row 1); nothing
	// else is touched — startupEvalPending is left alone so a
	// subsequent ReleaseBarrier can still run the branch-B recheck if
	// needed. If that recheck finds a new matched (!= nil), the auto
	// takeover rule applies (§5.6.2 手动优先) and the user's manual
	// selection may be overridden — which is consistent with "manual-
	// wins only on the same network".
	m.persistStateLocked(groupName, st)
}

// ReleaseBarrier signals that the per-group provider barrier has
// resolved (all referenced providers populated, or 15s timeout). Groups
// whose startupEvalPending is still true at this point run an internal
// evaluation per §5.6.2:
//   - if cached ctx present → full evaluation against that ctx
//     (§5.6.4 触发源 1)
//   - if no cached ctx → matched=<none> evaluation (§5.6.4 触发源 2)
//
// Callers (executor) should invoke this exactly once per group per
// manager lifetime; additional calls are harmless (no-op if the group
// has already cleared its pending flag).
func (m *Manager) ReleaseBarrier(groupName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	st, ok := m.states[groupName]
	if !ok {
		return
	}
	if st.barrierReleased {
		return
	}
	st.barrierReleased = true

	if !st.startupEvalPending {
		return
	}

	// Recheck: cached ctx or matched=<none>.
	var matched string
	var matchedPresent bool
	if m.ctx != nil {
		matched, matchedPresent = m.matchLocked(m.ctx)
	} else {
		matched = MatchedNone
		matchedPresent = true // §5.6.4 trigger source 2 treats as evaluated
	}

	// Evaluate but don't bother returning the result — barrier release is
	// an internal pathway, not a REST response.
	_ = m.evaluateGroupLocked(groupName, st, matched, matchedPresent, evalTriggerBarrierRelease)
	// missing_target on recheck keeps startupEvalPending=true conceptually,
	// but evaluateGroupLocked clears it on the auto/default paths. For
	// missing_target, we keep the bit set by NOT calling advanceState
	// (handled inside evaluateGroupLocked: missing_target returns early
	// before advanceState, so startupEvalPending remains true — matching
	// §5.6.2's "missing_target 保持 true" rule).
	//
	// Update the global atomicHasPendingMissingTarget to match the
	// current group states — otherwise a barrier-period missing_target
	// that resolved on release would keep the light path disabled
	// indefinitely until the next full evaluation.
	m.recomputePendingMissingTargetLocked()
}

// OnCandidateSetDirty marks the candidate-set-dirty flag so subsequent
// PUT requests go through the full evaluation path (§5.6.3 condition e).
// Called by the executor on provider subscription refresh / external
// provider reload / hot-reload group-membership changes.
//
// Uses an atomic increment rather than a boolean store so concurrent
// invocations during a full evaluation are not swallowed by the
// evaluation's end-of-cycle clear: PutContext snapshots the counter
// before evaluating and only clears via CompareAndSwap if the counter
// hasn't moved. A bump during evaluation keeps the signal live for the
// next PUT.
func (m *Manager) OnCandidateSetDirty() {
	m.atomicCandidateSetDirtyCounter.Add(1)
}

// GetStatus returns a read-only snapshot for GET /network/context.
func (m *Manager) GetStatus() *StatusResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := &StatusResult{HasContext: m.ctx != nil}
	if m.ctx != nil {
		result.Context = deepCopyContext(m.ctx)
		if m.ctxExpiresAt != nil {
			t := *m.ctxExpiresAt
			result.ExpiresAt = &t
		}
		// matched_network is a CTX-level property (§5.4.4 / §5.6.2),
		// not a per-group aggregate — recompute from the current ctx
		// directly. Using "first group's last_matched" would return
		// null in cases where every group sat on missing_target and
		// never advanced last_matched, even though the ctx clearly
		// matches a network.
		matched, present := m.matchLocked(m.ctx)
		result.MatchedNetworkPresent = present
		result.MatchedNetwork = matched

		age := int64(time.Since(m.ctxReceivedAt).Seconds())
		result.AgeSeconds = &age
	}

	result.Groups = make([]GroupStatus, 0, len(m.groupsOrder))
	for _, name := range m.groupsOrder {
		st, ok := m.states[name]
		if !ok {
			continue
		}
		g := m.groups[name]
		gs := GroupStatus{
			Group:                     name,
			CurrentProxy:              g.Now(),
			SelectionSource:           st.source,
			LastMatchedNetworkPresent: st.lastMatchedPresent,
			LastMatchedNetwork:        st.lastMatched,
		}
		result.Groups = append(result.Groups, gs)
	}

	return result
}

// ForceReEvaluate is called by the hot-reload path (§5.8.3) to run a
// single evaluation against the cached ctx, bypassing the stability
// short-circuit so YAML edits to policy take effect without waiting for
// a new PUT. No-op when no ctx is cached (§5.8.3 "无 ctx 不评估").
func (m *Manager) ForceReEvaluate() *PutResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ctx == nil {
		return nil
	}
	// ForceReEvaluate is a full evaluation (§5.8.3) — it also consumes
	// the candidate_set_dirty signal. Snapshot the counter BEFORE the
	// evaluation so a concurrent OnCandidateSetDirty during eval fails
	// the end-of-cycle CAS and keeps the signal live for the next PUT.
	dirtySnapshot := m.atomicCandidateSetDirtyCounter.Load()

	matched, matchedPresent := m.matchLocked(m.ctx)
	applied := make([]ApplyResult, 0, len(m.groupsOrder))
	for _, name := range m.groupsOrder {
		st, ok := m.states[name]
		if !ok {
			continue
		}
		res := m.evaluateGroupLocked(name, st, matched, matchedPresent, evalTriggerHotReload)
		applied = append(applied, res)
	}
	m.recomputePendingMissingTargetLocked()
	m.atomicCandidateSetDirtyCounter.CompareAndSwap(dirtySnapshot, 0)
	return &PutResult{
		MatchedNetworkPresent: matchedPresent,
		MatchedNetwork:        matched,
		Applied:               applied,
		ExpiresAt:             m.expiresAtSnapshot(),
	}
}

// expiresAtSnapshot returns a copy of ctxExpiresAt so callers can't
// modify internal state via the pointer.
func (m *Manager) expiresAtSnapshot() *time.Time {
	if m.ctxExpiresAt == nil {
		return nil
	}
	t := *m.ctxExpiresAt
	return &t
}

// stopTTLTimerLocked cancels any running TTL timer. Safe to call with
// nil m.ttlTimer. Also bumps ttlGen so any already-scheduled callback
// still in flight finds itself stale and exits on mu acquisition.
func (m *Manager) stopTTLTimerLocked() {
	m.ttlGen++
	if m.ttlTimer != nil {
		m.ttlTimer.Stop()
		m.ttlTimer = nil
	}
}

// startTTLTimerLocked schedules a callback that fires at expiresAt to
// clear the cached ctx (state-machine-preserving behavior, §5.4.3).
//
// Stale-fire guard: time.Timer.Stop() returns false for callbacks that
// are already scheduled-to-run or running, and Go has no way to revoke
// them. Without the generation stamp, a TTL renewal that races with the
// old timer's expiration would let the old callback wipe the new ctx
// after we've already replaced it. Each start increments ttlGen and
// captures it in the closure; onTTLExpired bails out when its captured
// gen no longer matches the manager's current.
func (m *Manager) startTTLTimerLocked(expiresAt time.Time) {
	m.ttlGen++
	gen := m.ttlGen
	dur := time.Until(expiresAt)
	if dur <= 0 {
		// Already expired; clear synchronously.
		m.ctx = nil
		m.ctxFingerprint = ""
		m.ctxExpiresAt = nil
		m.atomicHasCtx.Store(false)
		m.atomicCtxFingerprint.Store(nil)
		m.atomicCtxExpiresAtUnix.Store(0)
		return
	}
	m.ttlTimer = time.AfterFunc(dur, func() { m.onTTLExpired(gen) })
}

// onTTLExpired is the TTL timer callback. It reacquires mu, verifies
// the callback is not stale (generation stamp), drops the cached ctx,
// and leaves the state machine untouched per §5.4.3.
func (m *Manager) onTTLExpired(gen uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if gen != m.ttlGen {
		// A newer TTL renewal has superseded the one this callback was
		// scheduled for. Doing nothing — the current cached ctx belongs
		// to the renewal and its own timer will fire at the correct time.
		return
	}

	m.ttlTimer = nil
	m.ctx = nil
	m.ctxFingerprint = ""
	m.ctxExpiresAt = nil
	m.atomicHasCtx.Store(false)
	m.atomicCtxFingerprint.Store(nil)
	m.atomicCtxExpiresAtUnix.Store(0)
}

// deepCopyContext creates a new *NetworkContext whose Interfaces slice,
// every Subnets slice, Metered pointer, DNSSuffix, and TTL are freshly
// allocated (§5.6.3 "defensive deep-copy"). Derived fields are cleared
// and regenerated by NormalizeAndValidate at the call site.
func deepCopyContext(src *NetworkContext) *NetworkContext {
	if src == nil {
		return nil
	}
	dst := &NetworkContext{
		Version: src.Version,
	}
	if src.DNSSuffix != nil {
		dst.DNSSuffix = append([]string(nil), src.DNSSuffix...)
	}
	if src.TTL != nil {
		v := *src.TTL
		dst.TTL = &v
	}
	if src.Interfaces != nil {
		dst.Interfaces = make([]InterfaceContext, len(src.Interfaces))
		for i, iface := range src.Interfaces {
			copied := iface
			if iface.Subnets != nil {
				copied.Subnets = append([]string(nil), iface.Subnets...)
			}
			if iface.Metered != nil {
				v := *iface.Metered
				copied.Metered = &v
			}
			// Derived fields (subnetsParsed / gatewayIPParsed) are
			// repopulated by NormalizeAndValidate; zero them here so we
			// don't share parsed slices.
			copied.subnetsParsed = nil
			copied.gatewayIPParsed = netip.Addr{}
			dst.Interfaces[i] = copied
		}
	}
	return dst
}
