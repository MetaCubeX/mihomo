package networkpolicy

import (
	"encoding/json"
	"fmt"

	"github.com/metacubex/mihomo/component/profile/cachefile"
)

// PersistedState is the per-group record written to the cachefile's
// bucketNetworkPolicy. One entry per proxy-group that carries a
// network-policy (groups without a policy contribute nothing).
//
// The wire format is JSON, consistent with the rest of mihomo's bucket
// payloads. Field names match the in-memory state machine terminology:
//
//	{
//	  "schema_version": 1,
//	  "source": "auto" | "manual" | "unknown",
//	  "last_matched_network": null | "<name>" | "<none>"
//	}
//
// schema_version is the bucket-level format version, intentionally NOT
// reused with the PUT body `version` field (architecture §5.6.1). If a
// future release needs to evolve the persisted schema, bumping
// schema_version lets load-side gracefully fall back to "no bucket"
// (treated as branch B: cold-start, re-evaluate on first PUT) without
// blocking startup.
//
// last_matched_network encodes three internal states:
//   - JSON `null` → nil sentinel (never evaluated). `LastMatchedPresent
//     == false` on read. Legitimately reached two ways: branch B initial
//     state before any evaluation, and source=manual + nil when the
//     user flipped a group manually before any ctx PUT arrived.
//   - JSON string "<none>" → MatchedNone sentinel (evaluated, no
//     network matched). `LastMatchedPresent == true` with the literal
//     `<none>` value. Note: encoding/json escapes `<` and `>` by
//     default using the Unicode form `<` / `>` (NOT HTML
//     entities like `&lt;`), so the actual on-disk byte sequence
//     between the JSON string quotes is `\u003cnone\u003e` — 16 ASCII
//     characters. Unmarshal restores the logical 6-char `<none>`.
//     Raw bbolt inspection tools display the escaped form.
//   - JSON string "<name>" → matched network name. `LastMatchedPresent
//     == true`.
//
// REST-layer wire encoding (matched_network / last_matched_network in
// GET /network/context responses) is a separate concern handled by the
// manager: both the nil and <none> internal sentinels are flattened to
// JSON null on the wire, with host code using selection_source to
// disambiguate. Persistence keeps them distinct so the state machine
// can restart with fidelity.
type PersistedState struct {
	// SchemaVersion is the persisted-schema version tag; currently 1.
	SchemaVersion int `json:"schema_version"`

	// Source is the per-group selection source: "auto" / "manual" /
	// "unknown".
	Source string `json:"source"`

	// LastMatched is the saved last_matched_network value. An empty
	// string is ambiguous without LastMatchedPresent, so this field is
	// only authoritative when LastMatchedPresent is true.
	LastMatched string `json:"-"`

	// LastMatchedPresent distinguishes "never evaluated" (nil sentinel,
	// false) from "evaluated, possibly MatchedNone" (true). In JSON,
	// absent LastMatched key ↔ LastMatchedPresent=false. The exported
	// field is not serialized directly; see MarshalJSON / UnmarshalJSON.
	LastMatchedPresent bool `json:"-"`
}

// MarshalJSON emits last_matched_network as JSON null when absent, else
// as a string. Custom to route the LastMatchedPresent tri-state through
// a single JSON key (not two separate keys — simpler for future bucket
// consumers that only read this field for diagnostics).
func (p PersistedState) MarshalJSON() ([]byte, error) {
	type wire struct {
		SchemaVersion int     `json:"schema_version"`
		Source        string  `json:"source"`
		LastMatched   *string `json:"last_matched_network"`
	}
	w := wire{SchemaVersion: p.SchemaVersion, Source: p.Source}
	if p.LastMatchedPresent {
		v := p.LastMatched
		w.LastMatched = &v
	}
	return json.Marshal(w)
}

// UnmarshalJSON decodes the JSON form, populating LastMatchedPresent
// based on whether last_matched_network is a string (true) or null (false).
func (p *PersistedState) UnmarshalJSON(data []byte) error {
	type wire struct {
		SchemaVersion int     `json:"schema_version"`
		Source        string  `json:"source"`
		LastMatched   *string `json:"last_matched_network"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	p.SchemaVersion = w.SchemaVersion
	p.Source = w.Source
	if w.LastMatched != nil {
		p.LastMatched = *w.LastMatched
		p.LastMatchedPresent = true
	} else {
		p.LastMatched = ""
		p.LastMatchedPresent = false
	}
	return nil
}

// Validate checks for shape correctness and state-machine invariants.
// Returns a non-nil error for any obviously-corrupted or architecturally
// impossible record.
//
// Load-side: callers treat a validation error as "no bucket entry" and
// drop the state into branch B for that group, rather than feeding the
// corrupt value into the state machine.
//
// Write-side: raw json.Marshal on PersistedState bypasses Validate,
// and cachefile.SetNetworkPolicyState accepts any byte slice. The
// idiomatic (and only safe) write path is WriteNetworkPolicyState
// below, which chains Validate → json.Marshal → bucket Set. Writers
// that hand-roll the chain must call Validate explicitly; raw marshal
// + raw Set is a landmine this package deliberately does not booby-trap
// from the cachefile side (it owns opaque bytes on purpose so the
// schema stays in networkpolicy).
//
// Rejected impossible states (architecture §5.6.1 / §5.6.2 / §5.6.3):
//   - schema_version != current
//   - source not in {auto, manual, unknown}
//   - source == unknown in a persisted record: §5.6.3 only writes on
//     source/last_matched change, and unknown is the initial in-memory
//     state the manager transitions OUT of on the first evaluation —
//     so it is never a legitimate persisted value
//   - source == auto with LastMatchedPresent=false: auto implies the
//     state machine has run at least one evaluation (§5.6.2 shows every
//     transition that SETS source=auto also advances last_matched to
//     either a concrete name or MatchedNone), so the nil sentinel is
//     impossible here. source=manual + nil remains legitimate: the
//     user may flip a group manually before any ctx has been pushed,
//     leaving last_matched at the nil initial value.
//   - LastMatchedPresent=true with empty string: MatchedNone is the
//     correct sentinel for "evaluated, no match"; empty string has no
//     meaning in this encoding
//   - LastMatchedPresent=true with DefaultKey ("default"): default is
//     the policy-layer fallback key, never a network name
func (p PersistedState) Validate() error {
	if p.SchemaVersion != PersistVersion {
		return fmt.Errorf("schema_version %d not supported (current %d)", p.SchemaVersion, PersistVersion)
	}

	// Structural consistency first: the LastMatchedPresent flag and
	// LastMatched value must agree. Doing this before the source-specific
	// rules means programmers who forget to set LastMatchedPresent get a
	// targeted "inconsistent state" error rather than a downstream
	// "source=auto requires present" which obscures the real bug.
	if p.LastMatchedPresent {
		if p.LastMatched == "" {
			return fmt.Errorf("last_matched_network is present but empty (use JSON null to encode absence, <none> for evaluated-no-match)")
		}
		if p.LastMatched == DefaultKey {
			return fmt.Errorf("last_matched_network cannot be the reserved key %q", DefaultKey)
		}
	} else if p.LastMatched != "" {
		return fmt.Errorf("last_matched_network has value %q but LastMatchedPresent=false (inconsistent state; MarshalJSON would silently drop the value as null — set LastMatchedPresent=true or clear LastMatched)", p.LastMatched)
	}

	// State-machine rules: what combinations of source × LastMatchedPresent
	// are architecturally possible per §5.6.1 / §5.6.2 / §5.6.3.
	switch p.Source {
	case SourceAuto:
		if !p.LastMatchedPresent {
			return fmt.Errorf("source=%q requires last_matched_network to be present (§5.6.2 advances it on every transition that sets source=auto)", p.Source)
		}
	case SourceManual:
		// ok — manual + nil is legitimate (first manual set before ctx)
	case SourceUnknown:
		return fmt.Errorf("source=%q must not be persisted (impossible per §5.6.3; state machine only writes on source/last_matched change)", p.Source)
	default:
		return fmt.Errorf("invalid source %q", p.Source)
	}
	return nil
}

// MarshalValidated runs Validate, then json.Marshal. Returns the Validate
// error on any invariant failure so writers cannot accidentally persist an
// architecturally impossible state. Prefer this over json.Marshal(p) at
// write sites — the latter bypasses the invariant guard and will happily
// serialize source=unknown, auto+nil, present-false+nonempty, etc.
//
// For writing to the actual cachefile, WriteNetworkPolicyState combines
// this helper with the bucket Set call, closing the last hole where a
// caller could invoke json.Marshal + SetNetworkPolicyState directly and
// bypass validation.
func (p PersistedState) MarshalValidated() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// WriteNetworkPolicyState is the typed write-path entry point: validates
// the record, serializes it, and persists it through the cachefile bucket
// in one call. Returns Validate errors so callers can treat write failures
// uniformly. This is the only write path M3b's manager should use — going
// directly through cachefile.SetNetworkPolicyState with hand-marshaled
// bytes bypasses the state-machine invariants and lets corrupt records
// reach the bucket.
func WriteNetworkPolicyState(cache *cachefile.CacheFile, group string, state PersistedState) error {
	buf, err := state.MarshalValidated()
	if err != nil {
		return err
	}
	cache.SetNetworkPolicyState(group, buf)
	return nil
}
