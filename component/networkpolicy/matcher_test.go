package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func mustParse(t *testing.T, raw map[string]any) Matcher {
	t.Helper()
	m, err := ParseMatch(raw)
	assert.NoError(t, err)
	assert.NotNil(t, m)
	return m
}

func norm(t *testing.T, c *NetworkContext) *NetworkContext {
	t.Helper()
	assert.NoError(t, c.NormalizeAndValidate())
	return c
}

func TestParseMatch_Errors(t *testing.T) {
	cases := []struct {
		name   string
		raw    map[string]any
		errSub string
	}{
		{"empty", nil, "empty match block"},
		{"empty map", map[string]any{}, "empty match block"},
		{"unknown key", map[string]any{"ssidx": "a"}, "unknown match key"},
		{"metered disabled", map[string]any{"metered": true}, "not supported"},
		{"empty any", map[string]any{"any": []any{}}, "at least one sub-match"},
		{"empty all", map[string]any{"all": []any{}}, "at least one sub-match"},
		{"any non-map item", map[string]any{"any": []any{"string-not-map"}}, "expected map"},
		{"all non-list", map[string]any{"all": "not-a-list"}, "expected list"},
		{"not not a map", map[string]any{"not": []any{}}, "expected map"},
		{"not empty map", map[string]any{"not": map[string]any{}}, "empty match block"},
		{"empty field list", map[string]any{"ssid": []any{}}, "empty list"},
		{"non-string in list", map[string]any{"ssid": []any{"a", 123}}, "expected string"},
		{"empty string scalar", map[string]any{"ssid": ""}, "empty string"},
		{"empty string in list", map[string]any{"ssid": []any{"a", ""}}, "empty string"},
		{"gateway-ip invalid", map[string]any{"gateway-ip": "999.9.9.9"}, "gateway-ip[0]"},
		{"iface-type invalid enum", map[string]any{"iface-type": "tun"}, "invalid value"},
		{"iface-type wire invalid", map[string]any{"iface-type": "wire"}, "invalid value"},
		// Alphabetical key iteration — deterministic error for multi-bad blocks.
		{"deterministic error order", map[string]any{"zoo": "x", "all": []any{}}, "at least one sub-match"},
	}
	for _, tc := range cases {
		_, err := ParseMatch(tc.raw)
		assert.ErrorContains(t, err, tc.errSub, "case %q", tc.name)
	}
}

func TestParseMatch_Shape(t *testing.T) {
	// Single per-iface field → matchBlock with one-element ifacePred.
	m := mustParse(t, map[string]any{"ssid": "a"})
	b, ok := m.(matchBlock)
	assert.True(t, ok, "top-level per-iface field should wrap in matchBlock")
	assert.Len(t, b.ifacePred, 1)
	assert.Nil(t, b.globalPred)
	assert.Empty(t, b.combinators)

	// Multi per-iface fields → same matchBlock with multi-element ifacePred.
	m = mustParse(t, map[string]any{"ssid": "a", "iface-type": "wifi"})
	b = m.(matchBlock)
	assert.Len(t, b.ifacePred, 2, "atomic AND of two per-iface fields")

	// Only dns-suffix → matchBlock with only globalPred.
	m = mustParse(t, map[string]any{"dns-suffix": "corp"})
	b = m.(matchBlock)
	assert.Empty(t, b.ifacePred, "dns-suffix is global, not per-iface")
	assert.NotNil(t, b.globalPred)

	// Only any: with single sub → combinator unwrapped to the sub-matcher.
	m = mustParse(t, map[string]any{"any": []any{map[string]any{"ssid": "a"}}})
	b = m.(matchBlock)
	assert.Empty(t, b.ifacePred)
	assert.Nil(t, b.globalPred)
	assert.Len(t, b.combinators, 1)
	_, wrapped := b.combinators[0].(anyMatcher)
	assert.False(t, wrapped, "single-sub any: unwrapped to the sub directly")

	// any: with 2+ subs → actually wraps in anyMatcher type.
	m = mustParse(t, map[string]any{"any": []any{
		map[string]any{"ssid": "a"},
		map[string]any{"ssid": "b"},
	}})
	b = m.(matchBlock)
	assert.Len(t, b.combinators, 1)
	ae, ok := b.combinators[0].(anyMatcher)
	assert.True(t, ok, "2+ subs should wrap in anyMatcher")
	assert.Len(t, ae, 2)

	// all: with 2+ subs → allMatcher.
	m = mustParse(t, map[string]any{"all": []any{
		map[string]any{"iface-type": "vpn"},
		map[string]any{"ssid": "office"},
	}})
	b = m.(matchBlock)
	ae2, ok := b.combinators[0].(allMatcher)
	assert.True(t, ok, "2+ subs should wrap in allMatcher")
	assert.Len(t, ae2, 2)

	// not: always wraps in notMatcher (single arg, never unwrapped).
	m = mustParse(t, map[string]any{"not": map[string]any{"ssid": "x"}})
	b = m.(matchBlock)
	_, ok = b.combinators[0].(notMatcher)
	assert.True(t, ok)
}

// TestMatcher_PerIface covers per-iface field semantics.
func TestMatcher_PerIface(t *testing.T) {
	cases := []struct {
		name  string
		raw   map[string]any
		ctx   *NetworkContext
		want  bool
	}{
		// ssid
		{"ssid list hit", map[string]any{"ssid": []any{"a", "b"}},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", SSID: "b"}}}, true},
		{"ssid miss", map[string]any{"ssid": []any{"a", "b"}},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", SSID: "c"}}}, false},
		{"ssid empty interfaces", map[string]any{"ssid": "a"},
			&NetworkContext{Version: 1}, false},
		{"ssid null field on iface", map[string]any{"ssid": "a"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0"}}}, false},

		// bssid normalization both sides
		{"bssid dash hits colon ctx", map[string]any{"bssid": "AA-BB-CC-DD-EE-FF"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", BSSID: "aa:bb:cc:dd:ee:ff"}}}, true},
		{"bssid unseparated hits", map[string]any{"bssid": "AA-BB-CC-DD-EE-FF"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", BSSID: "AABBCCDDEEFF"}}}, true},

		// gateway-ip: exact + CIDR + v6 zoned
		{"gateway-ip exact", map[string]any{"gateway-ip": []any{"192.168.1.1", "10.0.0.0/8"}},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayIP: "192.168.1.1"}}}, true},
		{"gateway-ip cidr", map[string]any{"gateway-ip": []any{"192.168.1.1", "10.0.0.0/8"}},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayIP: "10.5.6.7"}}}, true},
		{"gateway-ip miss", map[string]any{"gateway-ip": []any{"192.168.1.1", "10.0.0.0/8"}},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayIP: "172.16.0.1"}}}, false},
		{"gateway-ip ipv6 zoned hits cidr", map[string]any{"gateway-ip": "fe80::/64"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayIP: "fe80::1%en0"}}}, true},

		// name
		{"name hit", map[string]any{"name": "wlan0"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0"}}}, true},
		{"name miss", map[string]any{"name": "wlan0"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "en0"}}}, false},

		// iface-type
		{"iface-type hit", map[string]any{"iface-type": "wifi"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", IfaceType: "wifi"}}}, true},
		{"iface-type miss", map[string]any{"iface-type": "wifi"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", IfaceType: "ethernet"}}}, false},

		// subnets (overlap)
		{"subnets overlap", map[string]any{"subnets": "10.0.0.0/8"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", Subnets: []string{"10.5.0.0/24"}}}}, true},
		{"subnets no overlap", map[string]any{"subnets": "10.0.0.0/8"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", Subnets: []string{"192.168.0.0/16"}}}}, false},
		{"subnets v4 no cross v6", map[string]any{"subnets": "10.0.0.0/8"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", Subnets: []string{"2001:db8::/32"}}}}, false},
		{"subnets wildcard v4 matches any v4", map[string]any{"subnets": "0.0.0.0/0"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", Subnets: []string{"10.0.0.0/8"}}}}, true},
		{"subnets wildcard v4 does not match v6", map[string]any{"subnets": "0.0.0.0/0"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", Subnets: []string{"2001:db8::/32"}}}}, false},

		// gateway-mac (hit / miss / null / list)
		{"gateway-mac hit single", map[string]any{"gateway-mac": "aa:bb:cc:dd:ee:ff"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayIP: "10.0.0.1", GatewayMAC: "AA-BB-CC-DD-EE-FF"}}}, true},
		{"gateway-mac miss", map[string]any{"gateway-mac": "aa:bb:cc:dd:ee:ff"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayIP: "10.0.0.1", GatewayMAC: "11:22:33:44:55:66"}}}, false},
		{"gateway-mac null on iface", map[string]any{"gateway-mac": "aa:bb:cc:dd:ee:ff"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0"}}}, false},
		{"gateway-mac list OR", map[string]any{"gateway-mac": []any{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayIP: "10.0.0.1", GatewayMAC: "11:22:33:44:55:66"}}}, true},
		{"gateway-mac normalized both sides", map[string]any{"gateway-mac": "AABBCCDDEEFF"},
			&NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayIP: "10.0.0.1", GatewayMAC: "aa-bb-cc-dd-ee-ff"}}}, true},
	}
	for _, tc := range cases {
		m := mustParse(t, tc.raw)
		ctx := norm(t, tc.ctx)
		assert.Equal(t, tc.want, m.Match(ctx), "case %q", tc.name)
	}
}

// TestMatcher_Atomicity covers the same-iface AND requirement for per-iface
// fields inside one match block.
func TestMatcher_Atomicity(t *testing.T) {
	raw := map[string]any{"ssid": "a", "iface-type": "wifi"}
	m := mustParse(t, raw)

	// Same iface satisfies both → true.
	ctx1 := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{
		{Name: "wlan0", SSID: "a", IfaceType: "wifi"},
	}})
	assert.True(t, m.Match(ctx1), "same iface satisfies both")

	// Two ifaces each satisfying one field → false (atomicity).
	ctx2 := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{
		{Name: "wlan0", SSID: "a", IfaceType: "ethernet"},
		{Name: "wlan1", SSID: "b", IfaceType: "wifi"},
	}})
	assert.False(t, m.Match(ctx2), "split across ifaces must not match")

	// Three ifaces where iface-C has both → true.
	ctx3 := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{
		{Name: "wlan0", SSID: "a", IfaceType: "ethernet"},
		{Name: "wlan1", SSID: "b", IfaceType: "wifi"},
		{Name: "wlan2", SSID: "a", IfaceType: "wifi"},
	}})
	assert.True(t, m.Match(ctx3), "third iface satisfies both")
}

// TestMatcher_Global covers dns-suffix as a global (top-level) predicate.
func TestMatcher_Global(t *testing.T) {
	m := mustParse(t, map[string]any{"dns-suffix": "Corp.Example.Com"})
	// Case-insensitive: parse-time lowercase vs normalize-time lowercase.
	ctx := norm(t, &NetworkContext{Version: 1, DNSSuffix: []string{"corp.example.com"}})
	assert.True(t, m.Match(ctx))

	// Empty interfaces + matching dns_suffix → matches (P_empty rule).
	ctx2 := norm(t, &NetworkContext{Version: 1, DNSSuffix: []string{"corp.example.com"}})
	assert.True(t, m.Match(ctx2))

	// Empty dns_suffix → no hit.
	ctx3 := norm(t, &NetworkContext{Version: 1})
	assert.False(t, m.Match(ctx3))

	// dns-suffix list: OR over matcher values intersecting ctx.
	m2 := mustParse(t, map[string]any{"dns-suffix": []any{"corp", "home"}})
	ctx4 := norm(t, &NetworkContext{Version: 1, DNSSuffix: []string{"home", "other"}})
	assert.True(t, m2.Match(ctx4))
}

// TestMatcher_Combinators covers any/all/not semantics.
func TestMatcher_Combinators(t *testing.T) {
	// any: OR over sub-blocks.
	mAny := mustParse(t, map[string]any{"any": []any{
		map[string]any{"ssid": "a"},
		map[string]any{"iface-type": "vpn"},
	}})
	ctx := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{
		{Name: "wg0", IfaceType: "vpn"},
	}})
	assert.True(t, mAny.Match(ctx))

	// all: AND over sub-blocks — different ifaces can satisfy each sub-block.
	mAll := mustParse(t, map[string]any{"all": []any{
		map[string]any{"iface-type": "vpn"},
		map[string]any{"iface-type": "wifi", "ssid": "home"},
	}})
	ctx2 := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{
		{Name: "wg0", IfaceType: "vpn"},
		{Name: "wlan0", IfaceType: "wifi", SSID: "home"},
	}})
	assert.True(t, mAll.Match(ctx2), "different ifaces each satisfy one sub-block")

	// not: negation.
	mNot := mustParse(t, map[string]any{"not": map[string]any{"iface-type": "cellular"}})
	ctx3 := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{
		{Name: "wlan0", IfaceType: "wifi"},
	}})
	assert.True(t, mNot.Match(ctx3), "no cellular iface present")

	// not: over empty interfaces[] → true (by design: "no iface satisfies"
	// reading is natural when no iface exists at all).
	ctx4 := norm(t, &NetworkContext{Version: 1})
	assert.True(t, mNot.Match(ctx4))

	// nested: not + any.
	mExclude := mustParse(t, map[string]any{"not": map[string]any{"any": []any{
		map[string]any{"iface-type": "cellular"},
		map[string]any{"iface-type": "wwan"},
	}}})
	assert.True(t, mExclude.Match(ctx3))
	ctxCell := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{
		{Name: "pdp_ip0", IfaceType: "cellular"},
	}})
	assert.False(t, mExclude.Match(ctxCell))
}

// TestMatcher_Mixed covers blocks with per-iface + global + combinator mixed.
func TestMatcher_Mixed(t *testing.T) {
	// iface-type: vpn AND dns-suffix: corp.
	m := mustParse(t, map[string]any{
		"iface-type": "vpn",
		"dns-suffix": "corp.example.com",
	})

	// Both satisfied → true.
	ctx1 := norm(t, &NetworkContext{
		Version:    1,
		Interfaces: []InterfaceContext{{Name: "wg0", IfaceType: "vpn"}},
		DNSSuffix:  []string{"corp.example.com"},
	})
	assert.True(t, m.Match(ctx1))

	// VPN present but no corp DNS → false.
	ctx2 := norm(t, &NetworkContext{
		Version:    1,
		Interfaces: []InterfaceContext{{Name: "wg0", IfaceType: "vpn"}},
	})
	assert.False(t, m.Match(ctx2))

	// Corp DNS but no VPN → false.
	ctx3 := norm(t, &NetworkContext{
		Version:   1,
		DNSSuffix: []string{"corp.example.com"},
	})
	assert.False(t, m.Match(ctx3))
}

// TestMatcher_NilCtx ensures the public Matcher surface is nil-safe:
// calling Match(nil) must return false rather than panic. Relevant for
// anyone using the Matcher interface outside of the top-level Match().
func TestMatcher_NilCtx(t *testing.T) {
	cases := []map[string]any{
		{"ssid": "a"},                                                        // matchBlock with ifacePred
		{"dns-suffix": "corp"},                                               // matchBlock with globalPred
		{"any": []any{map[string]any{"ssid": "a"}, map[string]any{"ssid": "b"}}}, // anyMatcher
		{"all": []any{map[string]any{"ssid": "a"}, map[string]any{"ssid": "b"}}}, // allMatcher
		{"not": map[string]any{"ssid": "a"}},                                 // notMatcher wrapping matchBlock
	}
	for i, raw := range cases {
		m := mustParse(t, raw)
		assert.NotPanics(t, func() {
			assert.False(t, m.Match(nil), "case %d: Match(nil) should be false", i)
		}, "case %d: Match(nil) should not panic", i)
	}
}

// TestMatcher_NullIfaceField covers: null-field iface is excluded from the
// ∃ domain, so both positive and `not:`-wrapped matchers behave consistently
// ("no iface satisfies" reading).
func TestMatcher_NullIfaceField(t *testing.T) {
	m := mustParse(t, map[string]any{"ssid": "office"})

	// Iface without ssid set → false (null excluded from ∃ domain).
	ctx := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{
		{Name: "wlan0"}, // no SSID
	}})
	assert.False(t, m.Match(ctx), "iface with null ssid doesn't hit")

	// Multiple ifaces: only the one with set ssid participates.
	ctx2 := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{
		{Name: "en0"},                 // null ssid
		{Name: "wlan0", SSID: "office"},
	}})
	assert.True(t, m.Match(ctx2))

	// not: over all-null → true (no iface has ssid=office).
	mNot := mustParse(t, map[string]any{"not": map[string]any{"ssid": "office"}})
	ctx3 := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{
		{Name: "wlan0"},
	}})
	assert.True(t, mNot.Match(ctx3))
}
