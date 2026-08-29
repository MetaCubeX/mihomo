package outboundgroup

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

func TestParseProxyGroupUsePrepend(t *testing.T) {
	t.Parallel()

	newEnv := func() (map[string]C.Proxy, map[string]P.ProxyProvider) {
		proxies := map[string]C.Proxy{
			"DIRECT":     adapter.NewProxy(outbound.NewDirect()),
			"REJECT":     adapter.NewProxy(outbound.NewReject()),
			"COMPATIBLE": adapter.NewProxy(outbound.NewCompatible()),
			"AUTO":       namedProxy("AUTO"),
		}
		providers := map[string]P.ProxyProvider{
			"pd1":      newStubProvider("pd1", "p1a", "p1b"),
			"pd2":      newStubProvider("pd2", "p2a"),
			"pd3":      newStubProvider("pd3", "p3a"),
			"^special": newStubProvider("^special", "s1"),
			"special":  newStubProvider("special", "s2"),
		}
		return proxies, providers
	}

	tests := []struct {
		name             string
		use              []string
		proxies          []string
		filter           string
		includeAllPd     bool
		allProviders     []string
		want             []string
		errContains      string
		withCompatiblePd bool
	}{
		{
			name:    "use appends after proxies by default",
			use:     []string{"pd1", "pd2"},
			proxies: []string{"DIRECT", "REJECT"},
			want:    []string{"DIRECT", "REJECT", "p1a", "p1b", "p2a"},
		},
		{
			name:    "caret prepends a provider before proxies",
			use:     []string{"^pd1"},
			proxies: []string{"DIRECT", "REJECT"},
			want:    []string{"p1a", "p1b", "DIRECT", "REJECT"},
		},
		{
			name:    "multiple carets keep listed order in front",
			use:     []string{"^pd1", "^pd2"},
			proxies: []string{"DIRECT"},
			want:    []string{"p1a", "p1b", "p2a", "DIRECT"},
		},
		{
			name:    "mixed caret and plain use",
			use:     []string{"^pd1", "pd2", "^pd3"},
			proxies: []string{"AUTO", "DIRECT"},
			want:    []string{"p1a", "p1b", "p3a", "AUTO", "DIRECT", "p2a"},
		},
		{
			name: "caret still orders in front when proxies is empty",
			use:  []string{"pd2", "^pd1"},
			want: []string{"p1a", "p1b", "p2a"},
		},
		{
			name:    "exact provider name starting with caret is not treated as prepend",
			use:     []string{"^special"},
			proxies: []string{"DIRECT"},
			want:    []string{"DIRECT", "s1"},
		},
		{
			name:    "double caret prepends a provider whose name starts with caret",
			use:     []string{"^^special"},
			proxies: []string{"DIRECT"},
			want:    []string{"s1", "DIRECT"},
		},
		{
			name:    "filter still applies to prepended providers",
			use:     []string{"^pd1", "pd2"},
			proxies: []string{"DIRECT"},
			filter:  "p1a|p2a",
			want:    []string{"p1a", "DIRECT", "p2a"},
		},
		{
			name:         "include-all-providers still appends after proxies",
			proxies:      []string{"DIRECT"},
			includeAllPd: true,
			allProviders: []string{"pd1", "pd2"},
			want:         []string{"DIRECT", "p1a", "p1b", "p2a"},
		},
		{
			name:        "unknown caret provider",
			use:         []string{"^missing"},
			proxies:     []string{"DIRECT"},
			errContains: "'^missing' not found",
		},
		{
			name:        "invalid caret-only use item",
			use:         []string{"^"},
			proxies:     []string{"DIRECT"},
			errContains: "invalid `use` item '^'",
		},
		{
			name:             "caret cannot reference a compatible provider",
			use:              []string{"^other-group"},
			proxies:          []string{"DIRECT"},
			withCompatiblePd: true,
			errContains:      "can't contains in `use`",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proxies, providers := newEnv()
			if tt.withCompatiblePd {
				hc := provider.NewHealthCheck([]C.Proxy{namedProxy("x")}, "", 0, 0, true, nil)
				pd, err := provider.NewCompatibleProvider("other-group", []C.Proxy{namedProxy("x")}, hc)
				require.NoError(t, err)
				providers["other-group"] = pd
			}

			config := map[string]any{
				"name": "GROUP",
				"type": "select",
			}
			if len(tt.use) > 0 {
				config["use"] = tt.use
			}
			if len(tt.proxies) > 0 {
				config["proxies"] = tt.proxies
			}
			if tt.filter != "" {
				config["filter"] = tt.filter
			}
			if tt.includeAllPd {
				config["include-all-providers"] = true
			}

			group, err := ParseProxyGroup(config, proxies, providers, nil, tt.allProviders)
			if tt.errContains != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.errContains)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, proxyNames(group))
		})
	}
}

func namedProxy(name string) C.Proxy {
	return adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: name}))
}

func proxyNames(g ProxyGroup) []string {
	ps := g.Proxies()
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		names = append(names, p.Name())
	}
	return names
}

type stubProvider struct {
	name    string
	proxies []C.Proxy
}

func newStubProvider(name string, proxyNames ...string) *stubProvider {
	proxies := make([]C.Proxy, 0, len(proxyNames))
	for _, proxyName := range proxyNames {
		proxies = append(proxies, namedProxy(proxyName))
	}
	return &stubProvider{name: name, proxies: proxies}
}

func (s *stubProvider) Name() string               { return s.name }
func (s *stubProvider) VehicleType() P.VehicleType { return P.Inline }
func (s *stubProvider) Type() P.ProviderType       { return P.Proxy }
func (s *stubProvider) Initial() error             { return nil }
func (s *stubProvider) Update() error              { return nil }
func (s *stubProvider) Proxies() []C.Proxy         { return s.proxies }
func (s *stubProvider) Count() int                 { return len(s.proxies) }
func (s *stubProvider) Touch()                     {}
func (s *stubProvider) HealthCheck()               {}
func (s *stubProvider) Version() uint32            { return 1 }
func (s *stubProvider) HealthCheckURL() string     { return "" }
func (s *stubProvider) RegisterHealthCheckTask(string, utils.IntRanges[uint16], string, uint) {
}
