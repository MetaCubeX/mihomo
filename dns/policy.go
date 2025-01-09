package dns

import (
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
)

type dnsPolicy interface {
	Match(domain string) []dnsClient
}

type domainTriePolicy struct {
	*trie.DomainTrie[[]dnsClient]
}

func (p domainTriePolicy) Match(domain string) []dnsClient {
	record := p.DomainTrie.Search(domain)
	if record != nil {
		return record.Data()
	}
	return nil
}

type domainMatcherPolicy struct {
	matcher    C.DomainMatcher
	dnsClients []dnsClient
}

func (p domainMatcherPolicy) Match(domain string) []dnsClient {
	if p.matcher.MatchDomain(domain) {
		return p.dnsClients
	}
	return nil
}
