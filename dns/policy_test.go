package dns

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
)

type policyDomainMatcher func(string) bool

func (m policyDomainMatcher) MatchDomain(domain string) bool { return m(domain) }

type policyIPMatcher func(netip.Addr) bool

func (m policyIPMatcher) MatchIp(ip netip.Addr) bool { return m(ip) }

func policyTestServers(name string) []NameServer {
	return []NameServer{{Net: "rcode", Addr: "success", Source: name}}
}

func TestPolicyMatchPrecedence(t *testing.T) {
	r := NewResolver(Config{
		Main: policyTestServers("main"),
		Policy: []Policy{
			{Domain: "+.example.com", NameServers: policyTestServers("suffix")},
			{Domain: "*.example.com", NameServers: policyTestServers("wildcard")},
			{Domain: "www.example.com", NameServers: policyTestServers("exact")},
			{Domain: "duplicate.test", NameServers: policyTestServers("old")},
			{Key: "duplicate.test,other.test", Domain: "duplicate.test", NameServers: policyTestServers("replacement")},
			{Key: "rule-set:one,two", Domain: "rule-set:two", Matcher: policyDomainMatcher(func(domain string) bool {
				return domain == "boundary.test" || domain == "late.example.com"
			}), NameServers: policyTestServers("matcher")},
			{Domain: "boundary.test", NameServers: policyTestServers("later-trie")},
			{Domain: "late.example.com", NameServers: policyTestServers("later-exact")},
		},
	}).Resolver
	cases := []struct {
		domain   string
		key      string
		matched  string
		upstream string
	}{
		{"example.com", "+.example.com", "+.example.com", "suffix"},
		{"deep.sub.example.com", "+.example.com", "+.example.com", "suffix"},
		{"sub.example.com", "*.example.com", "*.example.com", "wildcard"},
		{"WWW.EXAMPLE.COM.", "www.example.com", "www.example.com", "exact"},
		{"duplicate.test", "duplicate.test,other.test", "duplicate.test", "replacement"},
		{"boundary.test", "rule-set:one,two", "rule-set:two", "matcher"},
		{"late.example.com", "*.example.com", "*.example.com", "wildcard"},
	}
	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			match := r.MatchPolicy(tc.domain, D.TypeA)
			if match.Source != "policy" || match.Policy != tc.key || match.MatchedDomain != tc.matched ||
				!reflect.DeepEqual(match.Upstreams, []string{tc.upstream}) || match.Conditional {
				t.Fatalf("unexpected diagnostic: %+v", match)
			}
		})
	}
	if match := r.MatchPolicy("unmatched.test", D.TypeA); match.Source != "main" || match.Policy != "" || match.Conditional {
		t.Fatalf("unexpected unmatched diagnostic: %+v", match)
	}
}

func TestPolicyMatcherProvenanceAndNoHotPathAllocation(t *testing.T) {
	r := NewResolver(Config{Policy: []Policy{{
		Key: "geosite:cn,private", Domain: "geosite:private",
		Matcher:     policyDomainMatcher(func(string) bool { return true }),
		NameServers: []NameServer{{Net: "rcode", Addr: "success", Source: "rcode://success#disable-ipv6=true", Params: map[string]string{"disable-ipv6": "true"}}},
	}}}).Resolver
	m := &D.Msg{Question: []D.Question{{Name: "test.lan.", Qtype: D.TypeAAAA, Qclass: D.ClassINET}}}
	if allocations := testing.AllocsPerRun(100, func() { r.matchPolicy(m) }); allocations != 0 {
		t.Fatalf("runtime matcher allocated diagnostic data: %v", allocations)
	}
	match := r.MatchPolicy("test.lan", D.TypeAAAA)
	if match.Policy != "geosite:cn,private" || match.MatchedDomain != "geosite:private" ||
		!reflect.DeepEqual(match.Upstreams, []string{"rcode://success#disable-ipv6=true"}) {
		t.Fatalf("lost source provenance: %+v", match)
	}
	match.Upstreams[0] = "mutated"
	if r.MatchPolicy("test.lan", D.TypeAAAA).Upstreams[0] != "rcode://success#disable-ipv6=true" {
		t.Fatal("diagnostic caller can mutate stored upstream descriptions")
	}
}

type policyExchangeClient struct {
	calls         atomic.Int32
	ip            net.IP
	forbidAddress bool
}

func (c *policyExchangeClient) ExchangeContext(_ context.Context, m *D.Msg) (*D.Msg, error) {
	c.calls.Add(1)
	response := new(D.Msg)
	response.SetReply(m)
	if c.ip != nil {
		response.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET}, A: c.ip}}
	}
	return response, nil
}

func (c *policyExchangeClient) Address() string {
	if c.forbidAddress {
		panic("diagnostics must not inspect live client addresses")
	}
	return "test-upstream"
}
func (*policyExchangeClient) ResetConnection() {}

func TestPolicyMatchFallback(t *testing.T) {
	for _, lazy := range []bool{false, true} {
		r := NewResolver(Config{
			Main: policyTestServers("main"), Fallback: policyTestServers("fallback"), FallbackLazyQuery: lazy,
			FallbackDomainFilter: []C.DomainMatcher{policyDomainMatcher(func(domain string) bool { return domain == "fallback.test" || domain == "policy.test" })},
			Policy:               []Policy{{Domain: "policy.test", NameServers: policyTestServers("policy")}},
		}).Resolver
		mainClient, fallbackClient := &policyExchangeClient{forbidAddress: true}, &policyExchangeClient{forbidAddress: true}
		r.main, r.fallback = []dnsClient{mainClient}, []dnsClient{fallbackClient}
		for _, qtype := range []uint16{D.TypeA, D.TypeAAAA, D.TypeCNAME} {
			match := r.MatchPolicy("ordinary.test", qtype)
			if match.Source != "main-or-fallback" || !match.Conditional || match.Reason == "" ||
				!reflect.DeepEqual(match.Upstreams, []string{"main"}) || !reflect.DeepEqual(match.FallbackUpstreams, []string{"fallback"}) {
				t.Fatalf("lazy=%v: fallback must be conditional even without IP filters: %+v", lazy, match)
			}
			match = r.MatchPolicy("fallback.test", qtype)
			if match.Source != "fallback" || match.Conditional || !reflect.DeepEqual(match.Upstreams, []string{"fallback"}) {
				t.Fatalf("domain filter should select fallback: %+v", match)
			}
			if match = r.MatchPolicy("policy.test", qtype); match.Source != "policy" || match.Conditional {
				t.Fatalf("policy must take precedence over fallback: %+v", match)
			}
		}
		for _, qtype := range []uint16{D.TypeTXT, D.TypeHTTPS, D.TypeMX} {
			match := r.MatchPolicy("fallback.test", qtype)
			if match.Source != "main" || match.Conditional || len(match.FallbackUpstreams) != 0 {
				t.Fatalf("non-IP query must bypass fallback: %+v", match)
			}
		}
		if mainClient.calls.Load() != 0 || fallbackClient.calls.Load() != 0 {
			t.Fatal("offline diagnostics exchanged DNS messages")
		}
	}
}

func TestPolicyFallbackRuntimeBranches(t *testing.T) {
	cases := []struct {
		name       string
		qtype      uint16
		domainOnly bool
		mainIP     net.IP
		filter     bool
		wantMain   int32
		wantFall   int32
	}{
		{"domain", D.TypeA, true, nil, false, 0, 1},
		{"non-ip", D.TypeTXT, true, nil, false, 1, 0},
		{"empty-answer", D.TypeA, false, nil, false, 1, 1},
		{"accepted-ip", D.TypeA, false, net.IPv4(192, 0, 2, 1), false, 1, 0},
		{"filtered-ip", D.TypeA, false, net.IPv4(240, 0, 0, 1), true, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mainClient, fallbackClient := &policyExchangeClient{ip: tc.mainIP}, &policyExchangeClient{}
			r := &Resolver{
				main: []dnsClient{mainClient}, fallback: []dnsClient{fallbackClient},
				mainUpstreams: []string{"main"}, fallbackUpstreams: []string{"fallback"},
				cache: Config{}.newCache(), fallbackLazyQuery: true,
				fallbackDomainFilters: []C.DomainMatcher{policyDomainMatcher(func(string) bool { return tc.domainOnly })},
				fallbackIPFilters:     []C.IpMatcher{policyIPMatcher(func(netip.Addr) bool { return tc.filter })},
			}
			match := r.MatchPolicy("test.example", tc.qtype)
			m := &D.Msg{Question: []D.Question{{Name: "test.example.", Qtype: tc.qtype, Qclass: D.ClassINET}}}
			if _, err := r.ExchangeContext(context.Background(), m); err != nil {
				t.Fatal(err)
			}
			if mainClient.calls.Load() != tc.wantMain || fallbackClient.calls.Load() != tc.wantFall {
				t.Fatalf("unexpected runtime branches: main=%d fallback=%d diagnostic=%+v", mainClient.calls.Load(), fallbackClient.calls.Load(), match)
			}
			if tc.qtype == D.TypeTXT && match.Source != "main" || tc.qtype == D.TypeA && !tc.domainOnly && !match.Conditional {
				t.Fatalf("diagnostic incorrectly claims a definite route: %+v", match)
			}
		})
	}
}
