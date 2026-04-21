package networkpolicy

import (
	"sync"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"
)

// globalManager is the process-wide Manager accessor, installed by
// hub/executor.ApplyConfig and consumed by REST handlers (PUT /proxies
// hook that calls HandleManualSet, PUT/DELETE/GET /network/context
// handlers, and provider-update hooks).
//
// Guarded by globalMu so hot reloads that swap the manager don't race
// against concurrent readers. Readers call Global() which takes the
// lock briefly; Install() swaps under the lock. Manager itself has
// internal concurrency — the global mutex only protects the pointer
// swap.
//
// Lock ordering discipline for the REST layer (M4):
//
//   - globalMu → m.mu  (Install's inheritFrom acquires both; M4 code
//     that already holds globalMu via Global() and then acquires m.mu
//     via a manager method is consistent with this order).
//   - globalMu → sel.mu  (Install calls newSel.Set inside inheritFrom
//     while holding globalMu; REST handlers that hold a Selector's
//     internal mutex MUST NOT call Global() or any networkpolicy
//     package-level function, to avoid inversion deadlock).
//
// Specifically: PUT /proxies/:name handlers that call
// networkpolicy.Global().HandleManualSet(...) or similar must release
// the Selector lock BEFORE looking up Global(). The safest pattern is:
// do the Selector.Set() call as its own statement, then fetch Global()
// in a separate statement, then call HandleManualSet. If the Selector
// layer doesn't expose its mutex (and outboundgroup.Selector.Set does
// take an internal mutex), the ordering is satisfied implicitly
// because the caller never holds the Selector lock across the
// HandleManualSet call — they call Set, then call HandleManualSet.
//
// Known limitation: retaining a *Manager returned by Global() past the
// Install call that succeeded it leaves the caller operating on a
// detached instance. M4 REST handlers must re-fetch Global() at every
// entry point rather than cache the pointer at server-startup time.
// Codifying this via package-level PutContext/DeleteContext/etc
// wrappers is deferred to M4 where the REST dispatch is designed.
var (
	globalMu      sync.Mutex
	globalManager *Manager
)

// Global returns the currently-installed Manager, or nil if Install has
// not yet been called in this process. REST handlers and hooks should
// treat a nil return as "network-policy feature is off / not yet
// initialized" and skip their network-policy-specific logic.
func Global() *Manager {
	globalMu.Lock()
	defer globalMu.Unlock()
	return globalManager
}

// Install constructs a new Manager for the given configuration and
// publishes it as the global instance. On hot reload (second and later
// calls), it migrates in-memory state from the previous Manager per
// §5.8.3:
//   - groups that exist in both old and new: inherit source,
//     last_matched_network, startup_eval_pending, missingTargetPending
//   - groups added in the reload: start fresh per branch A / B init
//   - groups removed in the reload: state is dropped AND their
//     cachefile bucketNetworkPolicy entry is GC'd so a future reload
//     that reuses the same name starts clean
//
// Cachefile state is also consulted as a fallback, but in-memory state
// takes priority per §5.6.1 "内存中的状态与热重载：无论 store-selected
// 是否开启，进程内内存中的状态在配置热重载时始终保留".
//
// Critical: Install performs state migration + barrier release BEFORE
// atomically swapping the global pointer. Concurrent Global() readers
// see either the old Manager (fully initialized) or the new Manager
// (fully initialized) — never a half-migrated one. Without this
// ordering, a PUT / HandleManualSet / GetStatus racing with the
// migration could observe a Manager whose ctx / TTL / per-group state
// was still being copied.
//
// After migration (or first install), Install releases the provider
// barrier for every group. mihomo's executor loads proxy providers
// synchronously via loadProvider before calling Install, so this marks
// the cold-start provider wait as complete and runs the branch-B
// internal matched=<none> evaluation for any group that still has
// startup_eval_pending=true.
//
// Install does NOT call ForceReEvaluate — the caller decides whether
// the context-replay step of §5.8.3 is appropriate (e.g., on hot
// reload with a cached ctx). On a first-time cold start, ForceReEvaluate
// is a no-op so unconditional calls are safe.
func Install(networks []Network, groups []SelectorWithPolicy, cache *cachefile.CacheFile) *Manager {
	newMgr := NewManager(groups, networks, cache)

	// Hold globalMu for the entire Install so Global() readers block
	// until migration completes. Why the full-lock rather than a
	// snapshot-then-publish dance: the latter leaves a window where
	// Global() returns oldMgr but any writes (PUT /network/context,
	// HandleManualSet) land on the detached oldMgr AFTER inheritFrom
	// already snapshotted the pre-write state — the write is silently
	// dropped. Holding globalMu throughout forces concurrent readers to
	// wait; in-flight writers that had already dereferenced oldMgr take
	// old.mu, which inheritFrom also acquires, so they serialize cleanly
	// before migration begins.
	//
	// Install is typically sub-millisecond (state copy + per-group
	// ReleaseBarrier), and the executor-level mux in ApplyConfig
	// already serializes Install calls, so the additional blocking on
	// Global() is negligible in practice.
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalManager != nil {
		newMgr.inheritFrom(globalManager)
	}

	for _, g := range groups {
		newMgr.ReleaseBarrier(g.Name())
	}

	globalManager = newMgr
	return newMgr
}

// Uninstall clears the global Manager. Intended for shutdown paths and
// tests; not called by the executor during normal operation. Cancels
// any running TTL timer so a test's fake manager doesn't leak AfterFunc
// goroutines into the next test.
func Uninstall() {
	globalMu.Lock()
	old := globalManager
	globalManager = nil
	globalMu.Unlock()
	if old != nil {
		old.mu.Lock()
		old.stopTTLTimerLocked()
		old.mu.Unlock()
	}
}

// inheritFrom copies in-memory state from a predecessor Manager during
// hot reload. §5.8.3 rules:
//   - per-group: inherit source, last_matched_network (and presence),
//     startup_eval_pending, missingTargetPending for groups whose name
//     appears in both the old and new Manager. Groups absent from the
//     new Manager (dropped by hot reload) are silently discarded. Groups
//     new to the reload keep their NewManager-initialized state.
//   - cached ctx: if old had a ctx, re-adopt it in the new Manager,
//     including expires_at and the TTL timer. The fingerprint is
//     recomputed so the new Manager's light path can short-circuit on
//     subsequent identical PUTs. ctxReceivedAt is preserved so
//     GetStatus().AgeSeconds reflects age-since-last-host-PUT, not
//     age-since-reload.
//   - candidate_set_dirty / pending_missing_target atomic flags: a
//     reload changes group membership, which §5.6.3 treats as a
//     candidate-set change; we mark dirty so the next TTL heartbeat
//     forces a full evaluation. pending_missing_target is recomputed
//     from the migrated per-group bits.
func (newMgr *Manager) inheritFrom(old *Manager) {
	old.mu.Lock()
	defer old.mu.Unlock()
	newMgr.mu.Lock()
	defer newMgr.mu.Unlock()

	for name, oldSt := range old.states {
		newSt, ok := newMgr.states[name]
		if !ok {
			// Group dropped in the reload. GC its cachefile bucket
			// entry so a future reload that brings the same name back
			// doesn't resurrect state that is no longer authoritative
			// (§5.6.1: memory state is authoritative, and we've just
			// decided to forget this group in memory).
			if newMgr.cache != nil {
				newMgr.cache.DeleteNetworkPolicyState(name)
			}
			continue
		}
		// Inherit in-memory state. Overrides anything NewManager loaded
		// from the cachefile since in-memory state is authoritative for
		// groups that existed pre-reload (§5.6.1).
		newSt.source = oldSt.source
		newSt.lastMatched = oldSt.lastMatched
		newSt.lastMatchedPresent = oldSt.lastMatchedPresent
		newSt.startupEvalPending = oldSt.startupEvalPending
		newSt.missingTargetPending = oldSt.missingTargetPending
		// barrierReleased is NOT inherited: the new Manager starts with
		// its own barrier lifecycle so Install's ReleaseBarrier sweep
		// sees fresh state.

		// Migrate the selector's current proxy. In store-selected=true
		// mode, patchSelectGroup has already restored it from the
		// cachefile before updateNetworkPolicy runs, so the new
		// selector's Now() already matches. In store-selected=false
		// mode, patchSelectGroup is skipped and the new selector
		// defaults to COMPATIBLE — without this step, the user's last
		// manual choice would silently revert to default on hot reload,
		// leaving source=manual on a proxy that's no longer selected
		// (a mismatch §5.6.1 specifically forbids by promising in-
		// memory state survives reload).
		oldSel := old.groups[name]
		newSel := newMgr.groups[name]
		if oldSel != nil && newSel != nil {
			oldSelected := oldSel.Now()
			if oldSelected != "" && newSel.Now() != oldSelected && newSel.HasProxy(oldSelected) {
				if err := newSel.Set(oldSelected); err != nil {
					log.Warnln("[NetworkPolicy] group %q: could not migrate selected proxy %q across hot reload: %v", name, oldSelected, err)
				}
			}
		}
	}

	if old.ctx != nil {
		ctxCopy := deepCopyContext(old.ctx)
		if err := ctxCopy.NormalizeAndValidate(); err == nil {
			newMgr.ctx = ctxCopy
			newMgr.ctxFingerprint = ctxCopy.Fingerprint()
			newMgr.ctxReceivedAt = old.ctxReceivedAt
			fpCopy := newMgr.ctxFingerprint
			newMgr.atomicCtxFingerprint.Store(&fpCopy)
			newMgr.atomicHasCtx.Store(true)

			if old.ctxExpiresAt != nil {
				t := *old.ctxExpiresAt
				newMgr.ctxExpiresAt = &t
				newMgr.atomicCtxExpiresAtUnix.Store(t.UnixNano())
				newMgr.startTTLTimerLocked(t)
			}
		}
	}

	// Stop the old Manager's TTL timer. Its AfterFunc closure retains
	// a reference to the old Manager, which would otherwise keep the
	// entire state machine (selectors, providers, ctx, etc.) alive
	// until the original expiry fires — accumulating across consecutive
	// hot reloads. stopTTLTimerLocked also bumps old.ttlGen so any
	// callback already scheduled to run finds itself stale.
	old.stopTTLTimerLocked()

	// Group membership changed → candidate set is effectively dirty
	// (§5.6.3 "组成员列表变化（热重载）").
	newMgr.atomicCandidateSetDirtyCounter.Add(1)

	newMgr.recomputePendingMissingTargetLocked()
}
