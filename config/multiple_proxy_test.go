package config

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

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
