package provider

import (
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
)

type DomainSet struct {
	*domainStrategy
	adapter string
}

func (d *DomainSet) ProviderNames() []string {
	return nil
}

func (d *DomainSet) RuleType() C.RuleType {
	return C.DomainSet
}

func (d *DomainSet) Match(metadata *C.Metadata) (bool, string) {
	return d.domainStrategy.Match(metadata), d.adapter
}

func (d *DomainSet) Adapter() string {
	return d.adapter
}

func (d *DomainSet) Payload() string {
	return ""
}

func NewDomainSet(domainSet *trie.DomainSet, adapter string) *DomainSet {
	return &DomainSet{
		domainStrategy: &domainStrategy{domainSet: domainSet},
		adapter:        adapter,
	}
}

var _ C.Rule = (*DomainSet)(nil)
