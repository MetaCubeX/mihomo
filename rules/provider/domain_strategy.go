package provider

import (
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"golang.org/x/net/idna"
)

type domainStrategy struct {
	count       int
	domainRules *trie.DomainTrie[bool]
}

func (d *domainStrategy) Match(metadata *C.Metadata) bool {
	return d.domainRules != nil && d.domainRules.Search(metadata.Host) != nil
}

func (d *domainStrategy) Count() int {
	return d.count
}

func (d *domainStrategy) ShouldResolveIP() bool {
	return false
}

func (d *domainStrategy) OnUpdate(rules []string) {
	domainTrie := trie.New[bool]()
	count := 0
	for _, rule := range rules {
		actualDomain, _ := idna.ToASCII(rule)
		err := domainTrie.Insert(actualDomain, true)
		if err != nil {
			log.Warnln("invalid domain:[%s]", rule)
		} else {
			count++
		}
	}

	d.domainRules = domainTrie
	d.count = count
}

func NewDomainStrategy() *domainStrategy {
	return &domainStrategy{}
}
