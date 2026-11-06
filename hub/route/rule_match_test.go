package route

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/rules/wrapper"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/require"
)

func TestRuleMatchOffline(t *testing.T) {
	RP.SetTunnel(tunnel.Tunnel)
	oldRules, oldProviders := tunnel.Rules(), tunnel.RuleProviders()
	oldProxies, oldProxyProviders, oldMode := tunnel.Proxies(), tunnel.Providers(), tunnel.Mode()
	t.Cleanup(func() {
		tunnel.UpdateRules(oldRules, nil, oldProviders)
		tunnel.UpdateProxies(oldProxies, oldProxyProviders)
		tunnel.SetMode(oldMode)
	})
	direct := map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}
	tunnel.UpdateProxies(direct, nil)
	tunnel.SetMode(tunnel.Global)
	parse := func(t *testing.T, tp, payload string) C.RuleWrapper {
		t.Helper()
		rule, err := rules.ParseRule(tp, payload, "DIRECT", nil, nil)
		require.NoError(t, err)
		return wrapper.NewRuleWrapper(rule)
	}
	request := func(t *testing.T, query string) tunnel.RuleMatchResult {
		t.Helper()
		w := httptest.NewRecorder()
		ruleRouter().ServeHTTP(w, httptest.NewRequest("GET", "/match?"+query, nil))
		require.Equal(t, 200, w.Code, w.Body.String())
		var result tunnel.RuleMatchResult
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		return result
	}

	t.Run("missing process and disabled rules", func(t *testing.T) {
		notProcess := parse(t, "NOT", "((PROCESS-NAME,curl))")
		domain := parse(t, "DOMAIN-SUFFIX", "example.com")
		fallback := parse(t, "MATCH", "")
		tunnel.UpdateRules([]C.Rule{notProcess, domain, fallback}, nil, nil)
		result := request(t, "domain=www.example.com")
		require.False(t, result.Complete)
		require.Empty(t, result.Policy)
		require.Equal(t, []string{"process"}, result.Missing)
		result = request(t, "domain=www.example.com&process=curl")
		require.True(t, result.Complete)
		require.Equal(t, "DIRECT", result.Policy)
		require.Equal(t, "rule", result.Mode)
		require.NotNil(t, result.Rule)
		require.Equal(t, 1, result.Rule.Index)
		domain.SetDisabled(true)
		result = request(t, "domain=www.example.com&process=curl")
		require.True(t, result.Complete)
		require.NotNil(t, result.Rule)
		require.Equal(t, 2, result.Rule.Index)
		for _, rule := range []C.RuleWrapper{notProcess, domain, fallback} {
			require.Zero(t, rule.HitCount())
			require.Zero(t, rule.MissCount())
		}
	})

	t.Run("invalid parameters", func(t *testing.T) {
		for _, query := range []string{"", "domain=x&port=65536", "ip=bad", "domain=x&network=icmp", "domain=x&uid=-1", "domain=x&domain=y", "domain=x&unknown=1", "domain=x&resolve=", "domain=x&resolve=1", "domain=x&resolve=TRUE", "domain=x&resolve=true&resolve=false"} {
			w := httptest.NewRecorder()
			ruleRouter().ServeHTTP(w, httptest.NewRequest("GET", "/match?"+query, nil))
			require.Equal(t, 400, w.Code, query)
		}
	})

	t.Run("missing port blocks fallback", func(t *testing.T) {
		tunnel.UpdateRules([]C.Rule{parse(t, "DST-PORT", "443"), parse(t, "MATCH", "")}, nil, nil)
		result := request(t, "domain=www.example.com")
		require.False(t, result.Complete)
		require.Empty(t, result.Policy)
		require.Equal(t, []string{"port"}, result.Missing)
	})

	t.Run("nested subrules are evaluated once", func(t *testing.T) {
		leaf, fallback := parse(t, "DOMAIN-SUFFIX", "example.com"), parse(t, "MATCH", "")
		wrappedLeaf := wrapper.NewRuleWrapper(leaf)
		subs := map[string][]C.Rule{"inner": {wrappedLeaf, fallback}}
		inner, err := rules.ParseRule("SUB-RULE", "(DOMAIN-SUFFIX,example.com)", "inner", nil, subs)
		require.NoError(t, err)
		subs["outer"] = []C.Rule{wrapper.NewRuleWrapper(inner)}
		outer, err := rules.ParseRule("SUB-RULE", "(DOMAIN-SUFFIX,example.com)", "outer", nil, subs)
		require.NoError(t, err)
		tunnel.UpdateRules([]C.Rule{wrapper.NewRuleWrapper(outer)}, subs, nil)
		result := request(t, "domain=www.example.com")
		require.True(t, result.Complete)
		require.Equal(t, "DIRECT", result.Policy)
		require.Equal(t, []tunnel.RuleMatchLocation{
			{Index: 0, Type: leaf.RuleType().String(), Payload: leaf.Payload(), Name: "inner"},
			{Index: 0, Type: inner.RuleType().String(), Payload: inner.Payload(), Name: "outer"},
		}, result.SubRules)
		require.Zero(t, leaf.HitCount())
		require.Zero(t, leaf.MissCount())
		require.Zero(t, wrappedLeaf.HitCount())
		require.Zero(t, wrappedLeaf.MissCount())
		// The same shared traversal must not double-count live traffic either.
		matched, policy := outer.Match(&C.Metadata{Host: "www.example.com"}, C.RuleMatchHelper{})
		require.True(t, matched)
		require.Equal(t, "DIRECT", policy)
		require.EqualValues(t, 1, leaf.HitCount())
		require.EqualValues(t, 1, wrappedLeaf.HitCount())
		leaf.SetDisabled(true)
		result = request(t, "domain=www.example.com")
		require.True(t, result.Complete)
		require.Len(t, result.SubRules, 2)
		require.Equal(t, 1, result.SubRules[0].Index)
		require.Zero(t, fallback.HitCount())
	})

	t.Run("PASS UDP and REMATCH", func(t *testing.T) {
		t.Cleanup(func() { tunnel.UpdateProxies(direct, nil) })
		target := "child"
		rematch, err := outbound.NewRematch(outbound.RematchOption{Name: "again", TargetSubRule: &target})
		require.NoError(t, err)
		tunnel.UpdateProxies(map[string]C.Proxy{
			"DIRECT":   direct["DIRECT"],
			"again":    adapter.NewProxy(rematch),
			"skip":     adapter.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "skip", Type: C.Pass, UDP: true})),
			"tcp-only": adapter.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "tcp-only", Type: C.Direct})),
		}, nil)
		var top []C.Rule
		for _, policy := range []string{"skip", "tcp-only", "again"} {
			rule, err := rules.ParseRule("MATCH", "", policy, nil, nil)
			require.NoError(t, err)
			top = append(top, wrapper.NewRuleWrapper(rule))
		}
		disabled := parse(t, "DOMAIN-SUFFIX", "example.com")
		disabled.SetDisabled(true)
		tunnel.UpdateRules(top, map[string][]C.Rule{target: {disabled, parse(t, "MATCH", "")}}, nil)
		result := request(t, "domain=www.example.com&network=udp")
		require.True(t, result.Complete)
		require.Equal(t, "DIRECT", result.Policy)
		require.NotNil(t, result.Rule)
		require.Equal(t, target, result.Rule.Name)
		require.Equal(t, 1, result.Rule.Index)
	})

	for _, tc := range []struct {
		payload string
		query   string
		missing string
	}{
		{"DST-PORT,443", "domain=example.com&port=443", "source-port"},
		{"DST-PORT,443", "domain=example.com&source-port=443", ""},
		{"SRC-PORT,443", "domain=example.com&source-port=443", "port"},
		{"SRC-PORT,443", "domain=example.com&port=443", ""},
		{"IP-CIDR,192.0.2.0/24", "ip=192.0.2.1", "source-ip"},
		{"IP-CIDR,192.0.2.0/24", "domain=example.com&source-ip=192.0.2.1", ""},
		{"SRC-IP-CIDR,192.0.2.0/24", "domain=example.com&source-ip=192.0.2.1", "ip"},
	} {
		t.Run("source rule-set/"+tc.payload+"/"+tc.query, func(t *testing.T) {
			provider := RP.NewInlineProvider("source", P.Classical, []string{tc.payload}, rules.ParseRule)
			sourceRule, err := rules.ParseRule("RULE-SET", "source", "DIRECT", []string{"src"}, nil)
			require.NoError(t, err)
			tunnel.UpdateRules([]C.Rule{wrapper.NewRuleWrapper(sourceRule), parse(t, "MATCH", "")}, nil, map[string]P.RuleProvider{"source": provider})
			result := request(t, tc.query)
			if tc.missing == "" {
				require.True(t, result.Complete)
				require.Equal(t, "DIRECT", result.Policy)
				require.NotNil(t, result.Rule)
				require.Zero(t, result.Rule.Index)
			} else {
				require.False(t, result.Complete)
				require.Empty(t, result.Policy)
				require.Equal(t, []string{tc.missing}, result.Missing)
			}
		})
	}
}
