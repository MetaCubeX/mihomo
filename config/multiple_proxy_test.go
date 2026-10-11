package config

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	IN "github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
)

func TestMultipleProxyListenerType(t *testing.T) {
	cases := []struct {
		name    string
		entry   RawMultipleProxy
		wantT   string
		wantP   int
		wantErr bool
	}{
		{"mixed", RawMultipleProxy{MixedPort: 7890}, "mixed", 7890, false},
		{"http", RawMultipleProxy{Port: 7891}, "http", 7891, false},
		{"socks", RawMultipleProxy{SocksPort: 7892}, "socks", 7892, false},
		{"none", RawMultipleProxy{}, "", 0, true},
		{"two", RawMultipleProxy{MixedPort: 7890, Port: 7891}, "", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ltype, port, err := multipleProxyListenerType(c.entry)
			if c.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, c.wantT, ltype)
			assert.Equal(t, c.wantP, port)
		})
	}
}

func TestValidateMultipleProxyMode(t *testing.T) {
	assert.NoError(t, validateMultipleProxyMode(""))
	assert.NoError(t, validateMultipleProxyMode("global"))
	assert.NoError(t, validateMultipleProxyMode("rule"))
	assert.NoError(t, validateMultipleProxyMode("direct"))
	assert.NoError(t, validateMultipleProxyMode("GLOBAL"))
	assert.NoError(t, validateMultipleProxyMode("Rule"))
	assert.Error(t, validateMultipleProxyMode("bogus"))
}

func TestMultipleProxyListenerTypeUnnamedError(t *testing.T) {
	_, _, err := multipleProxyListenerType(RawMultipleProxy{MixedPort: 7890, Port: 7891})
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "multiple-proxy :")
	assert.Contains(t, err.Error(), "mixed-port=7890")
}

func TestCollectUsedPortsRange(t *testing.T) {
	cfg := &RawConfig{
		MixedPort: 7890,
		Listeners: []map[string]any{{"name": "x", "port": "8000-8002"}},
	}
	used, err := collectUsedPorts(cfg)
	assert.NoError(t, err)
	assert.Equal(t, "mixed-port", used[7890])
	assert.Contains(t, used[8000], "listener")
	assert.Contains(t, used[8001], "listener")
	assert.Contains(t, used[8002], "listener")
}

func TestCollectUsedPortsNumericPort(t *testing.T) {
	cfg := &RawConfig{
		Listeners: []map[string]any{{"name": "x", "port": 10808}},
	}
	used, err := collectUsedPorts(cfg)
	assert.NoError(t, err)
	assert.Contains(t, used[10808], "listener")
}

func TestCollectUsedPortsMissingAndBadPort(t *testing.T) {
	used, err := collectUsedPorts(&RawConfig{
		Listeners: []map[string]any{{"name": "no-port"}},
	})
	assert.NoError(t, err)
	assert.Empty(t, used)

	_, err = collectUsedPorts(&RawConfig{
		Listeners: []map[string]any{{"name": "bad", "port": "not-a-range"}},
	})
	assert.Error(t, err)
}

func TestMultipleProxyID(t *testing.T) {
	assert.Equal(t, "named", multipleProxyID(RawMultipleProxy{Name: "named"}, 3))
	assert.Equal(t, "multiple-proxy-3", multipleProxyID(RawMultipleProxy{}, 3))
}

func testProxiesMap(names ...string) map[string]C.Proxy {
	m := map[string]C.Proxy{
		"DIRECT":     adapter.NewProxy(outbound.NewDirect()),
		"COMPATIBLE": adapter.NewProxy(outbound.NewCompatible()),
		"GLOBAL":     adapter.NewProxy(outbound.NewDirect()), // stand-in group slot
	}
	for _, n := range names {
		m[n] = adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: n}))
	}
	return m
}

func TestBuildMatchsGroupUnionAndDefault(t *testing.T) {
	proxies := testProxiesMap("HK-01", "HK-02", "TW-01", "US-01")
	providers := map[string]P.ProxyProvider{}
	g, err := buildMatchsGroup("mp-0-group", []RawMatchsEntry{
		{Name: "*HK*"},
		{Name: "*TW*", DefaultSelected: "TW-01"},
	}, proxies, providers)
	assert.NoError(t, err)
	assert.Equal(t, "mp-0-group", g.Name())
	names := []string{}
	for _, p := range g.Adapter().(*outboundgroup.Selector).Proxies() {
		names = append(names, p.Name())
	}
	assert.ElementsMatch(t, []string{"HK-01", "HK-02", "TW-01"}, names)
	assert.Contains(t, proxies, "mp-0-group")
	assert.Contains(t, providers, "mp-0-group")
}

func TestBuildMatchsGroupErrors(t *testing.T) {
	proxies := testProxiesMap("HK-01")
	providers := map[string]P.ProxyProvider{}
	// 0 matches
	_, err := buildMatchsGroup("g0", []RawMatchsEntry{{Name: "*NOPE*"}}, proxies, providers)
	assert.Error(t, err)
	// inconsistent types
	proxies2 := testProxiesMap("HK-01", "TW-01")
	_, err = buildMatchsGroup("g1", []RawMatchsEntry{{Name: "*HK*", Type: "select"}, {Name: "*TW*", Type: "url-test"}}, proxies2, providers)
	assert.Error(t, err)
	// default-selected not in result
	_, err = buildMatchsGroup("g2", []RawMatchsEntry{{Name: "*HK*", DefaultSelected: "US-01"}}, testProxiesMap("HK-01"), providers)
	assert.Error(t, err)
}

func TestBuildMatchsGroupTypeResolution(t *testing.T) {
	providers := map[string]P.ProxyProvider{}

	// An omitted type is "select" per entry, so a bare pattern can not inherit
	// another entry's type.
	_, err := buildMatchsGroup("t0", []RawMatchsEntry{{Name: "*HK*"}, {Name: "*TW*", Type: "url-test"}}, testProxiesMap("HK-01", "TW-01"), providers)
	assert.Error(t, err)

	// Uniform non-select types are accepted.
	g, err := buildMatchsGroup("t1", []RawMatchsEntry{{Name: "*HK*", Type: "url-test"}, {Name: "*TW*", Type: "url-test"}}, testProxiesMap("HK-01", "TW-01"), providers)
	assert.NoError(t, err)
	assert.Equal(t, C.URLTest, g.Type())

	// An unsupported type is rejected.
	_, err = buildMatchsGroup("t2", []RawMatchsEntry{{Name: "*HK*", Type: "relay"}}, testProxiesMap("HK-01"), providers)
	assert.Error(t, err)
}

func TestBuildMatchsGroupDefaultSelectedRules(t *testing.T) {
	providers := map[string]P.ProxyProvider{}

	// default-selected is only supported on select groups.
	_, err := buildMatchsGroup("d0", []RawMatchsEntry{{Name: "*HK*", Type: "url-test", DefaultSelected: "HK-01"}}, testProxiesMap("HK-01"), providers)
	assert.Error(t, err)

	// Conflicting default-selected across entries is rejected.
	_, err = buildMatchsGroup("d1", []RawMatchsEntry{{Name: "*HK*", DefaultSelected: "HK-01"}, {Name: "*TW*", DefaultSelected: "TW-01"}}, testProxiesMap("HK-01", "TW-01"), providers)
	assert.Error(t, err)

	// A repeated identical default-selected is accepted.
	g, err := buildMatchsGroup("d2", []RawMatchsEntry{{Name: "*HK*", DefaultSelected: "HK-01"}, {Name: "*TW*", DefaultSelected: "HK-01"}}, testProxiesMap("HK-01", "TW-01"), providers)
	assert.NoError(t, err)
	assert.Equal(t, "HK-01", g.Adapter().(*outboundgroup.Selector).Now())
}

func TestBuildMatchsGroupAlternativeSplit(t *testing.T) {
	providers := map[string]P.ProxyProvider{}
	g, err := buildMatchsGroup("a0", []RawMatchsEntry{{Name: "*HK*|*TW*"}}, testProxiesMap("HK-01", "TW-01", "US-01"), providers)
	assert.NoError(t, err)
	names := []string{}
	for _, p := range g.Adapter().(*outboundgroup.Selector).Proxies() {
		names = append(names, p.Name())
	}
	assert.ElementsMatch(t, []string{"HK-01", "TW-01"}, names)
}

func TestBuildMatchsGroupSkipsReservedAndGroups(t *testing.T) {
	proxies := testProxiesMap("*") // note: literal name "*"
	providers := map[string]P.ProxyProvider{}
	g, err := buildMatchsGroup("g3", []RawMatchsEntry{{Name: "*"}}, proxies, providers)
	assert.NoError(t, err)
	names := []string{}
	for _, p := range g.Adapter().(*outboundgroup.Selector).Proxies() {
		names = append(names, p.Name())
	}
	assert.NotContains(t, names, "DIRECT")
	assert.NotContains(t, names, "COMPATIBLE")
}

func TestBuildPortRuleSetInsertBeforeMatch(t *testing.T) {
	global := []string{"DOMAIN-SUFFIX,a.com,DIRECT", "MATCH,GLOBAL"}
	entry := RawMultipleProxy{EnableGlobalRule: true, Rules: []string{"DOMAIN-SUFFIX,acl4.ssr,GLOBAL"}}
	name, merged := buildPortRuleSet(global, entry, "mp-0")
	assert.Equal(t, "mp-0-rules", name)
	assert.Equal(t, []string{
		"DOMAIN-SUFFIX,a.com,DIRECT",
		"DOMAIN-SUFFIX,acl4.ssr,GLOBAL",
		"MATCH,GLOBAL",
	}, merged)
}

func TestBuildPortRuleSetAppendWhenNoMatch(t *testing.T) {
	global := []string{"DOMAIN-SUFFIX,a.com,DIRECT"}
	entry := RawMultipleProxy{EnableGlobalRule: true, Rules: []string{"DOMAIN-SUFFIX,b.com,DIRECT"}}
	_, merged := buildPortRuleSet(global, entry, "mp-0")
	assert.Equal(t, []string{"DOMAIN-SUFFIX,a.com,DIRECT", "DOMAIN-SUFFIX,b.com,DIRECT"}, merged)
}

func TestBuildPortRuleSetNoIntent(t *testing.T) {
	name, merged := buildPortRuleSet([]string{"MATCH,GLOBAL"}, RawMultipleProxy{}, "mp-0")
	assert.Equal(t, "", name)
	assert.Nil(t, merged)
}

func TestBuildPortRuleSetOwnRulesOnly(t *testing.T) {
	entry := RawMultipleProxy{Rules: []string{"DOMAIN-SUFFIX,b.com,DIRECT"}}
	name, merged := buildPortRuleSet([]string{"MATCH,GLOBAL"}, entry, "mp-0")
	assert.Equal(t, "mp-0-rules", name)
	assert.Equal(t, []string{"DOMAIN-SUFFIX,b.com,DIRECT"}, merged)
}

func TestParseMultipleProxyPortConflict(t *testing.T) {
	cfg := &RawConfig{
		MixedPort:     7890,
		MultipleProxy: []RawMultipleProxy{{MixedPort: 7890}},
	}
	err := parseMultipleProxy(cfg, map[string]C.Proxy{}, map[string]P.ProxyProvider{}, map[string]P.RuleProvider{}, map[string][]C.Rule{}, map[string]C.InboundListener{})
	assert.Error(t, err)

	// A listeners: port range must also be expanded and conflict-checked at the
	// orchestration level, not only inside collectUsedPorts.
	rangeCfg := &RawConfig{
		Listeners:     []map[string]any{{"port": "8000-8002"}},
		MultipleProxy: []RawMultipleProxy{{MixedPort: 8001}},
	}
	err = parseMultipleProxy(rangeCfg, map[string]C.Proxy{}, map[string]P.ProxyProvider{}, map[string]P.RuleProvider{}, map[string][]C.Rule{}, map[string]C.InboundListener{})
	assert.Error(t, err)
}

func TestParseMultipleProxyWiresGroupRuleSetAndListener(t *testing.T) {
	cfg := &RawConfig{
		Rule: []string{"DOMAIN-SUFFIX,a.com,DIRECT", "MATCH,GLOBAL"},
		MultipleProxy: []RawMultipleProxy{
			{
				Name:             "mp-0",
				MixedPort:        7900,
				Mode:             "rule",
				EnableGlobalRule: true,
				Rules:            []string{"DOMAIN-SUFFIX,b.com,GLOBAL"},
				Matchs:           []RawMatchsEntry{{Name: "*HK*"}},
			},
			{
				// Uppercase is accepted by validation, so it must be normalized
				// to the lowercase key the runtime T.ModeMapping lookup uses.
				Name:      "mp-1",
				MixedPort: 7901,
				Mode:      "GLOBAL",
			},
		},
	}
	proxies := testProxiesMap("HK-01")
	providers := map[string]P.ProxyProvider{}
	ruleProviders := map[string]P.RuleProvider{}
	subRules := map[string][]C.Rule{}
	listeners := map[string]C.InboundListener{}

	err := parseMultipleProxy(cfg, proxies, providers, ruleProviders, subRules, listeners)
	assert.NoError(t, err)

	// exit group registered for API/dashboard use
	assert.Contains(t, proxies, "mp-0-group")
	assert.Contains(t, providers, "mp-0-group")

	// port scoped rule set: global base with the entry's rule before MATCH
	assert.Len(t, subRules["mp-0-rules"], 3)

	l, ok := listeners["mp-0"]
	assert.True(t, ok)
	option, ok := l.Config().(*IN.MixedOption)
	assert.True(t, ok)
	assert.Equal(t, "mp-0-rules", option.SpecialRules)
	assert.Equal(t, "rule", option.SpecialMode)
	assert.Equal(t, "mp-0-group", option.SpecialFallbackProxy)

	l1, ok := listeners["mp-1"]
	assert.True(t, ok)
	option1, ok := l1.Config().(*IN.MixedOption)
	assert.True(t, ok)
	assert.Equal(t, "global", option1.SpecialMode)
}

func TestParseMultipleProxyErrors(t *testing.T) {
	proxies := testProxiesMap("HK-01")

	// proxy-group must already exist
	err := parseMultipleProxy(&RawConfig{
		MultipleProxy: []RawMultipleProxy{{Name: "mp-0", MixedPort: 7900, ProxyGroup: "NOPE"}},
	}, proxies, map[string]P.ProxyProvider{}, map[string]P.RuleProvider{}, map[string][]C.Rule{}, map[string]C.InboundListener{})
	assert.Error(t, err)

	// a matchs entry is still validated when proxy-group wins
	err = parseMultipleProxy(&RawConfig{
		MultipleProxy: []RawMultipleProxy{{Name: "mp-0", MixedPort: 7900, ProxyGroup: "DIRECT", Matchs: []RawMatchsEntry{{Name: "*NOPE*"}}}},
	}, proxies, map[string]P.ProxyProvider{}, map[string]P.RuleProvider{}, map[string][]C.Rule{}, map[string]C.InboundListener{})
	assert.Error(t, err)

	// generated group name must be free
	proxies["mp-0-group"] = proxies["DIRECT"]
	err = parseMultipleProxy(&RawConfig{
		MultipleProxy: []RawMultipleProxy{{Name: "mp-0", MixedPort: 7900, Matchs: []RawMatchsEntry{{Name: "*HK*"}}}},
	}, proxies, map[string]P.ProxyProvider{}, map[string]P.RuleProvider{}, map[string][]C.Rule{}, map[string]C.InboundListener{})
	assert.Error(t, err)

	// generated rule set name must be free
	proxies = testProxiesMap("HK-01")
	err = parseMultipleProxy(&RawConfig{
		MultipleProxy: []RawMultipleProxy{{Name: "mp-0", MixedPort: 7900, Rules: []string{"MATCH,GLOBAL"}}},
	}, proxies, map[string]P.ProxyProvider{}, map[string]P.RuleProvider{},
		map[string][]C.Rule{"mp-0-rules": {}}, map[string]C.InboundListener{})
	assert.Error(t, err)

	// a listener name collision is rejected
	err = parseMultipleProxy(&RawConfig{
		MultipleProxy: []RawMultipleProxy{{Name: "mp-0", MixedPort: 7900}},
	}, proxies, map[string]P.ProxyProvider{}, map[string]P.RuleProvider{}, map[string][]C.Rule{},
		map[string]C.InboundListener{"mp-0": nil})
	assert.Error(t, err)

	// two entries on the same port conflict
	err = parseMultipleProxy(&RawConfig{
		MultipleProxy: []RawMultipleProxy{{Name: "mp-0", MixedPort: 7900}, {Name: "mp-1", MixedPort: 7900}},
	}, proxies, map[string]P.ProxyProvider{}, map[string]P.RuleProvider{}, map[string][]C.Rule{}, map[string]C.InboundListener{})
	assert.Error(t, err)

	// an invalid mode is rejected
	err = parseMultipleProxy(&RawConfig{
		MultipleProxy: []RawMultipleProxy{{Name: "mp-0", MixedPort: 7900, Mode: "bogus"}},
	}, proxies, map[string]P.ProxyProvider{}, map[string]P.RuleProvider{}, map[string][]C.Rule{}, map[string]C.InboundListener{})
	assert.Error(t, err)
}

// parseMultipleProxy is additive: it only ever adds listeners to the map it is
// handed. A reload that drops an entry relies on ParseRawConfig rebuilding the
// listener map from scratch, not on this function deleting anything — so a
// second parse into the SAME map must leave the first entry's listener intact.
// Kept at the map level on purpose: no sockets are started.
func TestParseMultipleProxyNeverRemovesListeners(t *testing.T) {
	proxies := testProxiesMap("HK-01")
	providers := map[string]P.ProxyProvider{}
	ruleProviders := map[string]P.RuleProvider{}
	subRules := map[string][]C.Rule{}

	listeners := map[string]C.InboundListener{}
	assert.NoError(t, parseMultipleProxy(
		&RawConfig{MultipleProxy: []RawMultipleProxy{{Name: "mp-0", MixedPort: 7900}}},
		proxies, providers, ruleProviders, subRules, listeners))
	assert.Contains(t, listeners, "mp-0")

	// An empty multiple-proxy slice must not evict the existing listener.
	assert.NoError(t, parseMultipleProxy(
		&RawConfig{MultipleProxy: []RawMultipleProxy{}},
		proxies, providers, ruleProviders, subRules, listeners))
	assert.Contains(t, listeners, "mp-0")
}

func TestBuildMatchsGroupSkipsExistingGroup(t *testing.T) {
	proxies := testProxiesMap("HK-01")
	selector, err := outboundgroup.NewSelector(
		outboundgroup.GroupCommonOption{Name: "EXISTING-GROUP"},
		outboundgroup.SelectorOption{},
		proxies["COMPATIBLE"],
		[]P.ProxyProvider{},
	)
	assert.NoError(t, err)
	proxies["EXISTING-GROUP"] = adapter.NewProxy(selector)

	providers := map[string]P.ProxyProvider{}
	g, err := buildMatchsGroup("g4", []RawMatchsEntry{{Name: "*"}}, proxies, providers)
	assert.NoError(t, err)
	names := []string{}
	for _, p := range g.Adapter().(*outboundgroup.Selector).Proxies() {
		names = append(names, p.Name())
	}
	assert.NotContains(t, names, "EXISTING-GROUP")
	assert.Contains(t, names, "HK-01")
}
