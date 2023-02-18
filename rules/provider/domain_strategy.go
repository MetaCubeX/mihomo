package provider

import (
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"golang.org/x/net/idna"
)

type domainStrategy struct {
	count       int
	domainRules *trie.DomainTrie[struct{}]
}

func (d *domainStrategy) ShouldFindProcess() bool {
	return false
}

func (d *domainStrategy) Match(metadata *C.Metadata) bool {
	return d.domainRules != nil && d.domainRules.Search(metadata.RuleHost()) != nil
}

func (d *domainStrategy) Count() int {
	return d.count
}

func (d *domainStrategy) ShouldResolveIP() bool {
	return false
}

func (d *domainStrategy) OnUpdate(rules []string) {
	domainTrie := trie.New[struct{}]()
	count := 0
	for _, rule := range rules {
		actualDomain, _ := idna.ToASCII(rule)
		err := domainTrie.Insert(actualDomain, struct{}{})
		if err != nil {
			log.Warnln("invalid domain:[%s]", rule)
		} else {
			count++
		}
	}
	domainTrie.Optimize()

	d.domainRules = domainTrie
	d.count = count
}

func NewDomainStrategy() *domainStrategy {
	return &domainStrategy{}
}
