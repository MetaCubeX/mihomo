package provider

import (
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
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
	domainTrie := trie.New[struct{}]()
	for _, rule := range rules {
		err := domainTrie.Insert(rule, struct{}{})
		if err != nil {
			log.Warnln("invalid domain:[%s]", rule)
		}
	}
	d.domainRules = domainTrie.NewDomainSet()
	d.count = len(rules)
}

func NewDomainStrategy() *domainStrategy {
	return &domainStrategy{}
}
