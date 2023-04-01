package provider

import (
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
)

type domainStrategy struct {
	count       int
	domainRules *trie.DomainSet
}

func (d *domainStrategy) ShouldFindProcess() bool {
	return false
}

func (d *domainStrategy) Match(metadata *C.Metadata) bool {
	return d.domainRules != nil && d.domainRules.Has(metadata.RuleHost())
}

func (d *domainStrategy) Count() int {
	return d.count
}

func (d *domainStrategy) ShouldResolveIP() bool {
	return false
}

func (d *domainStrategy) OnUpdate(rules []string) {
	domainTrie := trie.NewDomainSet(rules)
	d.domainRules = domainTrie
	d.count = len(rules)
}

func NewDomainStrategy() *domainStrategy {
	return &domainStrategy{}
}
