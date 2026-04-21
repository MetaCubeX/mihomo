package networkpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPersistedState_Roundtrip_ConcreteName(t *testing.T) {
	orig := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceManual,
		LastMatched:        "office",
		LastMatchedPresent: true,
	}
	buf, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(buf), `"last_matched_network":"office"`) {
		t.Errorf("want string-encoded last_matched_network, got %s", buf)
	}

	var decoded PersistedState
	if err := json.Unmarshal(buf, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded != orig {
		t.Errorf("roundtrip mismatch: want %+v got %+v", orig, decoded)
	}
}

// MatchedNone is a distinct state from nil (never evaluated), so the
// persisted form must preserve it as a string literal, not JSON null.
// Otherwise a restarted kernel would lose the "already evaluated, no
// network matched" history and re-enter the wrong §5.6.2 branch.
func TestPersistedState_Roundtrip_MatchedNone(t *testing.T) {
	orig := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceAuto,
		LastMatched:        MatchedNone,
		LastMatchedPresent: true,
	}
	buf, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// encoding/json escapes `<` and `>` to the Unicode form `<`
	// / `>` (NOT HTML entities), so the raw on-disk bytes between
	// the JSON string quotes are `<none>` — 16 ASCII chars
	// rather than the 6-char logical `<none>`. Harmless at rest; Unmarshal
	// restores the 6-char form. The semantic invariant we care about is
	// that the payload is a JSON string (not JSON null) and round-trips
	// to MatchedNone.
	s := string(buf)
	if strings.Contains(s, `"last_matched_network":null`) {
		t.Errorf("MatchedNone must serialize as string, not null; got %s", s)
	}
	// Assert the Unicode-escape form actually lands on disk. If a future
	// change disables HTML escaping via Encoder.SetEscapeHTML(false), this
	// assertion flips and the commit message / doc must be updated along
	// with it — the escape sequence IS the on-disk contract, so the test
	// guards it explicitly. The raw-string literal below contains the
	// literal backslash-u-003c-n-o-n-e-backslash-u-003e byte sequence.
	if !strings.Contains(s, `\u003cnone\u003e`) {
		t.Errorf(`want Unicode-escape form \u003cnone\u003e on disk, got %s`, s)
	}

	var decoded PersistedState
	if err := json.Unmarshal(buf, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.LastMatched != MatchedNone {
		t.Errorf("want decoded LastMatched == %q, got %q", MatchedNone, decoded.LastMatched)
	}
	if decoded != orig {
		t.Errorf("roundtrip mismatch: want %+v got %+v", orig, decoded)
	}
}

// Nil sentinel (never evaluated) is emitted as JSON null. Regression
// guard: the two absence representations (JSON null for nil, JSON
// "<none>" for MatchedNone) must not collapse at the encoding layer.
//
// Note: source=unknown paired with null last_matched is the in-memory
// initial state that Validate() intentionally rejects (§5.6.3 never
// persists it), so this test covers the *format layer only* — callers
// must treat a loaded record with these values as corrupt and fall into
// branch B. The separate Validate tests enforce that.
func TestPersistedState_Roundtrip_NilSentinel(t *testing.T) {
	orig := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceUnknown,
		LastMatched:        "",
		LastMatchedPresent: false,
	}
	buf, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(buf), `"last_matched_network":null`) {
		t.Errorf("want null-encoded last_matched_network, got %s", buf)
	}

	var decoded PersistedState
	if err := json.Unmarshal(buf, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.LastMatchedPresent {
		t.Errorf("null should decode as absent; got present=%v value=%q", decoded.LastMatchedPresent, decoded.LastMatched)
	}
	if decoded != orig {
		t.Errorf("roundtrip mismatch: want %+v got %+v", orig, decoded)
	}
}

func TestPersistedState_Validate_Happy(t *testing.T) {
	// Only auto and manual are valid persisted sources. Unknown is the
	// initial in-memory state the manager transitions OUT of on first
	// evaluation — never persisted, never valid on load.
	//
	// source=auto requires LastMatchedPresent=true (§5.6.2 advances it
	// on every transition that sets source=auto); source=manual + nil
	// is legitimate (first manual set before any ctx PUT).
	cases := []PersistedState{
		{SchemaVersion: PersistVersion, Source: SourceAuto, LastMatched: "office", LastMatchedPresent: true},
		{SchemaVersion: PersistVersion, Source: SourceAuto, LastMatched: MatchedNone, LastMatchedPresent: true},
		{SchemaVersion: PersistVersion, Source: SourceManual, LastMatched: "office", LastMatchedPresent: true},
		// manual + MatchedNone: reachable via §5.6.2 "default / no_change_no_default
		// advanced last_matched to <none>, user then manually switched".
		{SchemaVersion: PersistVersion, Source: SourceManual, LastMatched: MatchedNone, LastMatchedPresent: true},
		{SchemaVersion: PersistVersion, Source: SourceManual, LastMatched: "", LastMatchedPresent: false},
	}
	for _, p := range cases {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v should validate; got %v", p, err)
		}
	}
}

// source=auto paired with nil last_matched is architecturally impossible —
// §5.6.2's auto-setting transitions (matched / already_selected / default /
// no_change_no_default) all advance last_matched before leaving. The only
// legitimate `nil` is on source=manual (first manual set before ctx) or
// source=unknown (initial in-memory state, never persisted).
func TestPersistedState_Validate_RejectsAutoWithNil(t *testing.T) {
	p := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceAuto,
		LastMatched:        "",
		LastMatchedPresent: false,
	}
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "requires last_matched_network to be present") {
		t.Errorf("want auto+nil rejection, got %v", err)
	}
}

func TestPersistedState_Validate_RejectsUnknownSchema(t *testing.T) {
	p := PersistedState{SchemaVersion: 2, Source: SourceAuto}
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "schema_version 2") {
		t.Errorf("want schema_version error, got %v", err)
	}
}

func TestPersistedState_Validate_RejectsInvalidSource(t *testing.T) {
	p := PersistedState{SchemaVersion: PersistVersion, Source: "bogus"}
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid source") {
		t.Errorf("want invalid-source error, got %v", err)
	}
}

// source=unknown in a persisted record is architecturally impossible
// (§5.6.3 only writes on source/last_matched change, and unknown is the
// initial state, not a destination). Validate must reject it so a
// corrupted record falls through to branch B rather than propagating a
// broken state into the manager.
func TestPersistedState_Validate_RejectsPersistedUnknown(t *testing.T) {
	p := PersistedState{SchemaVersion: PersistVersion, Source: SourceUnknown}
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "must not be persisted") {
		t.Errorf("want persisted-unknown error, got %v", err)
	}
}

// last_matched_network = "" is impossible: absence is encoded via JSON
// null (LastMatchedPresent=false) and MatchedNone is the correct sentinel
// for "evaluated, no match". A present-but-empty value means the record
// was tampered with externally.
func TestPersistedState_Validate_RejectsEmptyLastMatched(t *testing.T) {
	p := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceAuto,
		LastMatched:        "",
		LastMatchedPresent: true,
	}
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "present but empty") {
		t.Errorf("want empty-last-matched error, got %v", err)
	}
}

// last_matched_network = "default" collides with the reserved policy-layer
// fallback key; it cannot be a real network name (ParseNetworks rejects
// it at config parse time). Reject defensively to catch external
// tampering.
func TestPersistedState_Validate_RejectsDefaultAsLastMatched(t *testing.T) {
	p := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceAuto,
		LastMatched:        DefaultKey,
		LastMatchedPresent: true,
	}
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "reserved key") {
		t.Errorf("want reserved-key error, got %v", err)
	}
}

// LastMatchedPresent=false paired with a non-empty LastMatched is an
// internally-inconsistent struct — MarshalJSON would drop the value as
// JSON null, losing information silently. Validate must catch this on
// the programmer-construction path.
func TestPersistedState_Validate_RejectsInconsistentAbsenceWithValue(t *testing.T) {
	p := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceManual,
		LastMatched:        "office",
		LastMatchedPresent: false,
	}
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "LastMatchedPresent=false") {
		t.Errorf("want inconsistent-absence error, got %v", err)
	}
}

// MatchedNone as LastMatched is explicitly valid: "evaluated, no network
// matched" is a legitimate persisted state.
func TestPersistedState_Validate_AcceptsMatchedNone(t *testing.T) {
	p := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceAuto,
		LastMatched:        MatchedNone,
		LastMatchedPresent: true,
	}
	if err := p.Validate(); err != nil {
		t.Errorf("MatchedNone should validate; got %v", err)
	}
}

// Legacy buckets written by older releases may lack fields we added later;
// the JSON decoder should handle missing fields without crashing. The
// resulting struct fails Validate (schema_version=0) so callers still fall
// through to branch B — the point of this test is that decoding itself is
// robust, not that the result is usable.
func TestPersistedState_Unmarshal_MissingFields(t *testing.T) {
	var p PersistedState
	if err := json.Unmarshal([]byte(`{}`), &p); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	if p.LastMatchedPresent {
		t.Errorf("missing key should decode as absent; got present")
	}
	if p.SchemaVersion != 0 || p.Source != "" {
		t.Errorf("zero-value expected; got %+v", p)
	}
}

func TestPersistedState_Unmarshal_Malformed(t *testing.T) {
	var p PersistedState
	err := json.Unmarshal([]byte(`not json`), &p)
	if err == nil {
		t.Errorf("want error on malformed input; got nil")
	}
}

// MarshalValidated returns the Validate error on invariant violations so
// writers cannot leak impossible states onto disk via raw json.Marshal.
func TestPersistedState_MarshalValidated_RejectsInvalid(t *testing.T) {
	invalid := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceAuto,
		LastMatched:        "",
		LastMatchedPresent: false,
	}
	_, err := invalid.MarshalValidated()
	if err == nil {
		t.Errorf("want Validate error on auto+nil, got nil")
	}
	// Raw json.Marshal succeeds on the same invalid struct — this is the
	// loophole MarshalValidated is designed to close. The assertion
	// documents the contract rather than testing json semantics.
	if _, rawErr := json.Marshal(invalid); rawErr != nil {
		t.Errorf("raw json.Marshal should succeed on invalid struct (MarshalValidated is the guard); got %v", rawErr)
	}
}

func TestPersistedState_MarshalValidated_PassesThrough(t *testing.T) {
	valid := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceAuto,
		LastMatched:        "office",
		LastMatchedPresent: true,
	}
	buf, err := valid.MarshalValidated()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded PersistedState
	if err := json.Unmarshal(buf, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded != valid {
		t.Errorf("roundtrip mismatch: want %+v got %+v", valid, decoded)
	}
}

// When a caller constructs LastMatchedPresent=false + LastMatched="office"
// + Source=auto, the most diagnostic error is the inconsistency, not
// "auto requires present". Structural checks run first so the reported
// error points at the real bug.
func TestPersistedState_Validate_InconsistencyTakesPrecedenceOverSource(t *testing.T) {
	p := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceAuto,
		LastMatched:        "office",
		LastMatchedPresent: false,
	}
	err := p.Validate()
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if !strings.Contains(err.Error(), "LastMatchedPresent=false") {
		t.Errorf("want inconsistent-state error (structural check first), got %v", err)
	}
}

// Same inconsistency on the manual branch — structural check is
// source-agnostic, so manual + "office" + Present=false must also be
// caught with the inconsistent-state diagnostic (manual + nil is
// otherwise legitimate, so source-specific check alone wouldn't catch
// the bug).
func TestPersistedState_Validate_InconsistencyOnManual(t *testing.T) {
	p := PersistedState{
		SchemaVersion:      PersistVersion,
		Source:             SourceManual,
		LastMatched:        "office",
		LastMatchedPresent: false,
	}
	err := p.Validate()
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if !strings.Contains(err.Error(), "LastMatchedPresent=false") {
		t.Errorf("want inconsistent-state error on manual branch, got %v", err)
	}
}
