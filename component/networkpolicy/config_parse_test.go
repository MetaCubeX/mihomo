package networkpolicy

import (
	"strings"
	"testing"
)

// --- ParseNetworks -------------------------------------------------------

func TestParseNetworks_Empty(t *testing.T) {
	got, err := ParseNetworks(nil)
	if err != nil {
		t.Fatalf("ParseNetworks(nil): unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ParseNetworks(nil): want empty, got %d entries", len(got))
	}

	got, err = ParseNetworks([]map[string]any{})
	if err != nil {
		t.Fatalf("ParseNetworks(empty slice): unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ParseNetworks(empty slice): want empty, got %d", len(got))
	}
}

func TestParseNetworks_Happy(t *testing.T) {
	raw := []map[string]any{
		{"name": "office", "match": map[string]any{"ssid": "office-5g", "iface-type": "wifi"}},
		{"name": "home", "match": map[string]any{"gateway-mac": "aa:bb:cc:dd:ee:00"}},
		{"name": "anywhere", "match": map[string]any{"dns-suffix": "corp.example.com"}},
	}
	got, err := ParseNetworks(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 networks, got %d", len(got))
	}
	if got[0].Name != "office" || got[1].Name != "home" || got[2].Name != "anywhere" {
		t.Errorf("unexpected names: %q %q %q", got[0].Name, got[1].Name, got[2].Name)
	}
	for i := range got {
		if got[i].Matcher == nil {
			t.Errorf("entry %d has nil matcher", i)
		}
	}
}

func TestParseNetworks_ReservedNames(t *testing.T) {
	for _, name := range []string{DefaultKey, MatchedNone} {
		raw := []map[string]any{
			{"name": name, "match": map[string]any{"ssid": "x"}},
		}
		_, err := ParseNetworks(raw)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("name %q: want reserved error, got %v", name, err)
		}
	}
}

func TestParseNetworks_DuplicateName(t *testing.T) {
	raw := []map[string]any{
		{"name": "office", "match": map[string]any{"ssid": "a"}},
		{"name": "office", "match": map[string]any{"ssid": "b"}},
	}
	_, err := ParseNetworks(raw)
	if err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Errorf("want duplicate-name error, got %v", err)
	}
}

func TestParseNetworks_MissingName(t *testing.T) {
	raw := []map[string]any{
		{"match": map[string]any{"ssid": "a"}},
	}
	_, err := ParseNetworks(raw)
	if err == nil || !strings.Contains(err.Error(), "missing name") {
		t.Errorf("want missing-name error, got %v", err)
	}
}

func TestParseNetworks_EmptyName(t *testing.T) {
	raw := []map[string]any{{"name": "", "match": map[string]any{"ssid": "a"}}}
	_, err := ParseNetworks(raw)
	if err == nil || !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("want empty-name error, got %v", err)
	}
}

func TestParseNetworks_NonStringName(t *testing.T) {
	raw := []map[string]any{{"name": 42, "match": map[string]any{"ssid": "a"}}}
	_, err := ParseNetworks(raw)
	if err == nil || !strings.Contains(err.Error(), "name must be string") {
		t.Errorf("want string-name error, got %v", err)
	}
}

func TestParseNetworks_MissingMatch(t *testing.T) {
	raw := []map[string]any{{"name": "office"}}
	_, err := ParseNetworks(raw)
	if err == nil || !strings.Contains(err.Error(), "missing match") {
		t.Errorf("want missing-match error, got %v", err)
	}
}

func TestParseNetworks_MatchNotMap(t *testing.T) {
	raw := []map[string]any{{"name": "office", "match": "oops"}}
	_, err := ParseNetworks(raw)
	if err == nil || !strings.Contains(err.Error(), "match must be a map") {
		t.Errorf("want match-not-map error, got %v", err)
	}
}

func TestParseNetworks_UnknownTopLevelKey(t *testing.T) {
	raw := []map[string]any{{"name": "office", "match": map[string]any{"ssid": "a"}, "priority": 1}}
	_, err := ParseNetworks(raw)
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("want unknown-key error, got %v", err)
	}
}

func TestParseNetworks_EmptyEntry(t *testing.T) {
	raw := []map[string]any{{}}
	_, err := ParseNetworks(raw)
	if err == nil || !strings.Contains(err.Error(), "empty entry") {
		t.Errorf("want empty-entry error, got %v", err)
	}
}

func TestParseNetworks_MeteredRejected(t *testing.T) {
	// metered matcher is disabled at ParseMatch level; ensure the error
	// surfaces via ParseNetworks (no silent acceptance).
	raw := []map[string]any{
		{"name": "x", "match": map[string]any{"metered": true}},
	}
	_, err := ParseNetworks(raw)
	if err == nil || !strings.Contains(err.Error(), "metered") {
		t.Errorf("want metered error, got %v", err)
	}
}

func TestParseNetworks_UnknownMatchKeyPropagates(t *testing.T) {
	raw := []map[string]any{
		{"name": "x", "match": map[string]any{"bogus": "v"}},
	}
	_, err := ParseNetworks(raw)
	if err == nil || !strings.Contains(err.Error(), "unknown match key") {
		t.Errorf("want propagated unknown-match-key error, got %v", err)
	}
}

// --- ParseGroupPolicy ----------------------------------------------------

func TestParseGroupPolicy_Happy_StaticProxy(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"hk", "us", "DIRECT"}}
	global := []string{"hk", "us", "DIRECT"}
	raw := map[string]any{
		"office":  "hk",
		"home":    "DIRECT",
		"default": "us",
	}
	p, err := ParseGroupPolicy(raw, []string{"office", "home"}, global, source)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Mapping["office"] != "hk" || p.Mapping["home"] != "DIRECT" {
		t.Errorf("unexpected mapping: %v", p.Mapping)
	}
	// Guard against a future regression that writes the default into Mapping;
	// TestParseGroupPolicy_DefaultKeyAllowed only covers the default-only case.
	if len(p.Mapping) != 2 {
		t.Errorf("mapping should only contain non-default keys, got %v", p.Mapping)
	}
	if !p.HasDefault || p.DefaultProxy != "us" {
		t.Errorf("default not captured: hasDefault=%v defaultProxy=%q", p.HasDefault, p.DefaultProxy)
	}
}

func TestParseGroupPolicy_ProviderTolerant(t *testing.T) {
	// target "auto-fill" is not in StaticProxies AND not in globalProxyNames;
	// HasProvider=true → parse-time tolerant (target may come from subscription).
	source := GroupSource{StaticProxies: []string{"DIRECT"}, HasProvider: true}
	global := []string{"DIRECT"} // auto-fill NOT in globals → tolerant branch
	raw := map[string]any{"office": "auto-fill"}
	_, err := ParseGroupPolicy(raw, []string{"office"}, global, source)
	if err != nil {
		t.Errorf("provider-backed target should be tolerant; got %v", err)
	}
}

// Architecture §5.8.1 row 4: target exists globally but is not reachable
// from this group is fail-fast regardless of HasProvider. Provider
// expansions contribute names disjoint from the global proxy set, so any
// global name this group can't reach is a definite misconfiguration.
func TestParseGroupPolicy_GlobalButUnreachable_FailsEvenWithProvider(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"DIRECT"}, HasProvider: true}
	global := []string{"DIRECT", "someOtherGroup"}
	raw := map[string]any{"office": "someOtherGroup"}
	_, err := ParseGroupPolicy(raw, []string{"office"}, global, source)
	if err == nil || !strings.Contains(err.Error(), "not reachable by this group") {
		t.Errorf("want global-but-unreachable error even with HasProvider=true; got %v", err)
	}
}

func TestParseGroupPolicy_UnknownTargetNoProvider(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"DIRECT"}, HasProvider: false}
	global := []string{"DIRECT"}
	raw := map[string]any{"office": "oops"}
	_, err := ParseGroupPolicy(raw, []string{"office"}, global, source)
	if err == nil || !strings.Contains(err.Error(), "not found anywhere") {
		t.Errorf("want missing-target error, got %v", err)
	}
}

func TestParseGroupPolicy_UnknownNetworkName(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"hk"}}
	raw := map[string]any{"undefined-net": "hk"}
	_, err := ParseGroupPolicy(raw, []string{"office"}, []string{"hk"}, source)
	if err == nil || !strings.Contains(err.Error(), "unknown network") {
		t.Errorf("want unknown-network error, got %v", err)
	}
}

func TestParseGroupPolicy_DefaultKeyAllowed(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"DIRECT"}}
	raw := map[string]any{"default": "DIRECT"}
	p, err := ParseGroupPolicy(raw, []string{}, []string{"DIRECT"}, source)
	if err != nil {
		t.Fatalf("default-only policy should parse; got %v", err)
	}
	if !p.HasDefault || p.DefaultProxy != "DIRECT" {
		t.Errorf("default not applied: %+v", p)
	}
	if len(p.Mapping) != 0 {
		t.Errorf("mapping should be empty, got %v", p.Mapping)
	}
}

func TestParseGroupPolicy_MatchedNoneReserved(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"hk"}}
	raw := map[string]any{"<none>": "hk"}
	_, err := ParseGroupPolicy(raw, []string{"office"}, []string{"hk"}, source)
	if err == nil || !strings.Contains(err.Error(), "reserved sentinel") {
		t.Errorf("want reserved-sentinel error, got %v", err)
	}
}

func TestParseGroupPolicy_EmptyMap(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"hk"}}
	raw := map[string]any{}
	_, err := ParseGroupPolicy(raw, []string{"office"}, []string{"hk"}, source)
	if err == nil || !strings.Contains(err.Error(), "empty map") {
		t.Errorf("want empty-map error, got %v", err)
	}
}

func TestParseGroupPolicy_NonMapRaw(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"hk"}}
	_, err := ParseGroupPolicy("oops", []string{"office"}, []string{"hk"}, source)
	if err == nil || !strings.Contains(err.Error(), "expected map") {
		t.Errorf("want expected-map error, got %v", err)
	}
}

func TestParseGroupPolicy_NonStringTarget(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"hk"}}
	raw := map[string]any{"office": 42}
	_, err := ParseGroupPolicy(raw, []string{"office"}, []string{"hk"}, source)
	if err == nil || !strings.Contains(err.Error(), "target must be string") {
		t.Errorf("want string-target error, got %v", err)
	}
}

func TestParseGroupPolicy_EmptyTarget(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"hk"}}
	raw := map[string]any{"office": ""}
	_, err := ParseGroupPolicy(raw, []string{"office"}, []string{"hk"}, source)
	if err == nil || !strings.Contains(err.Error(), "target cannot be empty") {
		t.Errorf("want empty-target error, got %v", err)
	}
}

// When a reserved key (<none>) carries a malformed target, the reserved-key
// error should win — otherwise users chase the wrong problem first. Regression
// guard: key validation must run before target shape validation.
func TestParseGroupPolicy_ReservedKeyTakesPrecedenceOverTargetShape(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"hk"}}
	raw := map[string]any{"<none>": 42}
	_, err := ParseGroupPolicy(raw, []string{"office"}, []string{"hk"}, source)
	if err == nil || !strings.Contains(err.Error(), "reserved sentinel") {
		t.Errorf("want reserved-sentinel error to take precedence over target shape; got %v", err)
	}
}

// Same ordering guard for unknown-network keys: unknown-network must be
// reported before a bad target shape.
func TestParseGroupPolicy_UnknownNetworkTakesPrecedenceOverTargetShape(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"hk"}}
	raw := map[string]any{"bogus-net": 42}
	_, err := ParseGroupPolicy(raw, []string{"office"}, []string{"hk"}, source)
	if err == nil || !strings.Contains(err.Error(), "unknown network") {
		t.Errorf("want unknown-network error to take precedence over target shape; got %v", err)
	}
}

// Default target itself must pass the reachability check — a default that
// references a proxy not in the group's candidate set is just as broken
// as a per-network mapping that does.
func TestParseGroupPolicy_DefaultTargetReachabilityChecked(t *testing.T) {
	source := GroupSource{StaticProxies: []string{"DIRECT"}, HasProvider: false}
	raw := map[string]any{"default": "bogus"}
	_, err := ParseGroupPolicy(raw, []string{}, []string{"DIRECT"}, source)
	if err == nil || !strings.Contains(err.Error(), "not found anywhere") {
		t.Errorf("want default-reachability error, got %v", err)
	}
}
