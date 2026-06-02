package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatch(t *testing.T) {
	m1, _ := ParseMatch(map[string]any{"ssid": "office"})
	m2, _ := ParseMatch(map[string]any{"ssid": []any{"office", "home"}})
	networks := []Network{
		{Name: "office-net", Matcher: m1},
		{Name: "shared", Matcher: m2},
	}

	// First hit wins — not "shared" even though it also matches.
	ctx := &NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", SSID: "office"}}}
	_ = ctx.NormalizeAndValidate()
	name, ok := Match(networks, ctx)
	assert.True(t, ok)
	assert.Equal(t, "office-net", name)

	// No hits → ("", false).
	ctx = &NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", SSID: "unknown"}}}
	_ = ctx.NormalizeAndValidate()
	name, ok = Match(networks, ctx)
	assert.False(t, ok)
	assert.Equal(t, "", name)

	// nil ctx / empty list / nil matcher entries: never hit, never panic.
	name, ok = Match(networks, nil)
	assert.False(t, ok)
	assert.Equal(t, "", name)

	name, ok = Match(nil, ctx)
	assert.False(t, ok)
	assert.Equal(t, "", name)

	// A nil-matcher entry must be skipped rather than treated as a match.
	entries := []Network{{Name: "broken"}, {Name: "office-net", Matcher: m1}}
	ctx = &NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", SSID: "office"}}}
	_ = ctx.NormalizeAndValidate()
	name, ok = Match(entries, ctx)
	assert.True(t, ok)
	assert.Equal(t, "office-net", name)
}
