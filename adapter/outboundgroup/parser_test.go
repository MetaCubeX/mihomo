package outboundgroup

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestParseProxyGroupRejectsInvalidRegex(t *testing.T) {
	for _, option := range []string{"filter", "exclude-filter"} {
		for _, includeAll := range []bool{false, true} {
			t.Run(option+"/"+map[bool]string{false: "explicit", true: "include-all"}[includeAll], func(t *testing.T) {
				config := map[string]any{
					"name":                "test",
					"type":                "select",
					"proxies":             []string{"DIRECT"},
					"include-all-proxies": includeAll,
					option:                "valid`[",
				}
				proxies := map[string]C.Proxy{
					"DIRECT":     adapter.NewProxy(outbound.NewDirect()),
					"COMPATIBLE": adapter.NewProxy(outbound.NewCompatible()),
				}
				group, err := ParseProxyGroup(config, proxies, map[string]P.ProxyProvider{}, []string{"DIRECT"}, nil)
				if err == nil || group != nil {
					t.Fatalf("got group=%v, err=%v; want an invalid regex error", group, err)
				}
				if !strings.Contains(err.Error(), "test") || !strings.Contains(err.Error(), option) {
					t.Fatalf("error should identify the group and option: %v", err)
				}
			})
		}
	}
}
