package config

import (
	"testing"

	"github.com/metacubex/mihomo/common/orderedmap"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/dns"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/tunnel"

	D "github.com/miekg/dns"
)

func TestNameServerPolicySourceProvenance(t *testing.T) {
	const key = "Example.COM,+.private.test"
	const upstream = "rcode://success#disable-ipv6=true"
	policies := orderedmap.New[string, any]()
	policies.Set(key, []string{upstream})
	parsed, err := parseNameServerPolicy(policies, "dns.nameserver-policy", nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	r := dns.NewResolver(dns.Config{Policy: parsed}).Resolver
	for _, domain := range []string{"example.com", "sub.private.test"} {
		match := r.MatchPolicy(domain, D.TypeA)
		if match.Source != "policy" || match.Policy != key || len(match.Upstreams) != 1 || match.Upstreams[0] != upstream {
			t.Fatalf("parsed policy provenance lost at resolver construction: %+v", match)
		}
	}
}

func TestNameServerPolicyMatcherKeepsExpandedAndOriginalKeys(t *testing.T) {
	const key = "RULE-SET:first,second"
	providers := map[string]P.RuleProvider{
		"first":  RP.NewInlineProvider("first", P.Domain, []string{"first.test"}, nil),
		"second": RP.NewInlineProvider("second", P.Domain, []string{"second.test"}, nil),
	}
	RP.SetTunnel(tunnel.Tunnel)
	previousRules, previousProviders := tunnel.Rules(), tunnel.RuleProviders()
	t.Cleanup(func() { tunnel.UpdateRules(previousRules, nil, previousProviders) })
	tunnel.UpdateRules(previousRules, nil, providers)
	policies := orderedmap.New[string, any]()
	policies.Set(key, []string{"rcode://success"})
	parsed, err := parseNameServerPolicy(policies, "dns.nameserver-policy", providers, false, false)
	if err != nil {
		t.Fatal(err)
	}
	r := dns.NewResolver(dns.Config{Policy: parsed}).Resolver
	for _, domain := range []string{"first", "second"} {
		match := r.MatchPolicy(domain+".test", D.TypeA)
		if match.Source != "policy" || match.Policy != key || match.MatchedDomain != "rule-set:"+domain {
			t.Fatalf("expanded rule-set policy did not match %s: %+v", domain, match)
		}
	}
}

func TestNameServerSourceDoesNotChangeDeduplication(t *testing.T) {
	servers, err := parseNameServer([]string{"192.0.2.1", "udp://192.0.2.1:53"}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].Source != "192.0.2.1" {
		t.Fatalf("upstream source spelling must not change runtime deduplication: %+v", servers)
	}
}
