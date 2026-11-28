package dns

import (
	"net/url"
	"strings"

	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
)

// policyTarget is constructed once and shared by runtime and diagnostic matches.
type policyTarget struct {
	dnsClients []dnsClient
	key        string
	domain     string
	upstreams  []string
}

type dnsPolicy interface {
	Match(domain string) *policyTarget
}

type domainTriePolicy struct {
	*trie.DomainTrie[*policyTarget]
}

func (p domainTriePolicy) Match(domain string) *policyTarget {
	record := p.DomainTrie.Search(domain)
	if record != nil {
		return record.Data()
	}
	return nil
}

type domainMatcherPolicy struct {
	matcher C.DomainMatcher
	target  *policyTarget
}

func (p domainMatcherPolicy) Match(domain string) *policyTarget {
	if p.matcher.MatchDomain(domain) {
		return p.target
	}
	return nil
}

// PolicyMatch describes upstream selection without sending a DNS request.
// Conditional means the main response is needed to choose between main and fallback.
type PolicyMatch struct {
	Domain            string   `json:"domain"`
	Type              string   `json:"type"`
	Source            string   `json:"source"`
	Policy            string   `json:"policy,omitempty"`
	MatchedDomain     string   `json:"matched_domain,omitempty"`
	Upstreams         []string `json:"upstreams"`
	FallbackUpstreams []string `json:"fallback_upstreams,omitempty"`
	Conditional       bool     `json:"conditional"`
	Reason            string   `json:"reason,omitempty"`
}

// MatchPolicy describes resolver upstream selection without querying upstreams or
// consulting the cache. DNS server middleware (hosts, fake-IP, IPv6 filtering) is
// outside this resolver-level diagnostic, just as it is for /dns/query.
func (r *Resolver) MatchPolicy(domain string, qtype uint16) PolicyMatch {
	m := &D.Msg{Question: []D.Question{{Name: D.Fqdn(domain), Qtype: qtype, Qclass: D.ClassINET}}}
	match := PolicyMatch{
		Domain: msgToDomain(m),
		Type:   D.Type(qtype).String(),
	}
	if target := r.matchPolicy(m); target != nil {
		match.Source = "policy"
		match.Policy = target.key
		match.MatchedDomain = target.domain
		match.Upstreams = append([]string{}, target.upstreams...)
		return match
	}
	match.Source = "main"
	upstreams := r.mainUpstreams
	// Only A, AAAA and CNAME queries use ipExchange and its fallback logic.
	if isIPRequest(m.Question[0]) && r.fallback != nil {
		if r.shouldOnlyQueryFallback(m) {
			match.Source = "fallback"
			upstreams = r.fallbackUpstreams
			match.Reason = "fallback domain filter matched"
		} else {
			match.Source = "main-or-fallback"
			match.Conditional = true
			match.FallbackUpstreams = append([]string{}, r.fallbackUpstreams...)
			match.Reason = "fallback is used if main fails, returns no IP addresses, or an IP matches fallback-filter"
		}
	}
	match.Upstreams = append([]string{}, upstreams...)
	return match
}

// describeNameServers snapshots configuration, never dynamic client addresses
// (system and DHCP clients may inspect external state to report their addresses).
func describeNameServers(servers []NameServer) []string {
	descriptions := make([]string, 0, len(servers))
	for _, server := range servers {
		if server.Source != "" {
			descriptions = append(descriptions, server.Source)
			continue
		}
		description := server.Addr
		if !strings.Contains(description, "://") {
			scheme := server.Net
			if scheme == "" {
				scheme = "udp"
			}
			description = scheme + "://" + description
		}
		params := url.Values{}
		for key, value := range server.Params {
			params.Set(key, value)
		}
		fragment := params.Encode()
		if server.ProxyName != "" {
			if fragment != "" {
				fragment += "&"
			}
			fragment += server.ProxyName
		}
		if fragment != "" {
			description += "#" + fragment
		}
		descriptions = append(descriptions, description)
	}
	return descriptions
}
