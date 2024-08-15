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

type domainRulePolicy struct {
	rule       C.Rule
	dnsClients []dnsClient
}

func (p domainRulePolicy) Match(domain string) []dnsClient {
	if ok, _ := p.rule.Match(&C.Metadata{Host: domain}); ok {
		return p.dnsClients
	}
	return nil
}
