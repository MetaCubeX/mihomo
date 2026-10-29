package outboundgroup

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type healthCheckProxy struct {
	C.Proxy
	name  string
	kind  C.AdapterType
	tests atomic.Int32
}

func (p *healthCheckProxy) Name() string        { return p.name }
func (p *healthCheckProxy) Type() C.AdapterType { return p.kind }
func (p *healthCheckProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	p.tests.Add(1)
	return 1, nil
}
func (p *healthCheckProxy) AliveForTestUrl(string) bool       { return true }
func (p *healthCheckProxy) LastDelayForTestUrl(string) uint16 { return 1 }

func TestCompatibleProviderHealthCheckExclusions(t *testing.T) {
	for _, test := range []struct {
		name    string
		options map[string]any
		want    []int32
	}{
		{"no exclusions", nil, []int32{1, 1, 1}},
		{"exclude filter", map[string]any{"exclude-filter": "Japan`Singapore"}, []int32{1, 0, 0}},
		{"exclude type", map[string]any{"exclude-type": "reject"}, []int32{1, 1, 0}},
		{"all excluded", map[string]any{"exclude-filter": ".*"}, []int32{0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			members := []*healthCheckProxy{
				{name: "France", kind: C.Direct},
				{name: "Japan", kind: C.Direct},
				{name: "Singapore", kind: C.Reject},
			}
			mapping := map[string]C.Proxy{"COMPATIBLE": adapter.NewProxy(outbound.NewCompatible())}
			names := make([]string, 0, len(members))
			for _, member := range members {
				mapping[member.name] = member
				names = append(names, member.name)
			}
			options := map[string]any{
				"name":                "group",
				"type":                "url-test",
				"include-all-proxies": true,
				"url":                 "http://example.com/generate_204",
			}
			for name, value := range test.options {
				options[name] = value
			}
			providers := map[string]P.ProxyProvider{}
			_, err := ParseProxyGroup(options, mapping, providers, names, nil)
			if err != nil {
				t.Fatal(err)
			}
			provider := providers["group"]
			t.Cleanup(func() { _ = provider.(interface{ Close() error }).Close() })
			provider.HealthCheck()
			for i, member := range members {
				if got := member.tests.Load(); got != test.want[i] {
					t.Errorf("%s health checks = %d, want %d", member.name, got, test.want[i])
				}
			}
		})
	}
}
