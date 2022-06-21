package provider

import (
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"strings"
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
		err := domainTrie.Insert(rule, true)
		if err != nil {
			log.Warnln("invalid domain:[%s]", rule)
		} else {
			count++
		}
	}

	d.domainRules = domainTrie
	d.count = count
}

func ruleParse(ruleRaw string) (string, string, []string) {
	item := strings.Split(ruleRaw, ",")
	if len(item) == 1 {
		return "", item[0], nil
	} else if len(item) == 2 {
		return item[0], item[1], nil
	} else if len(item) > 2 {
		return item[0], item[1], item[2:]
	}

	return "", "", nil
}

func NewDomainStrategy() *domainStrategy {
	return &domainStrategy{}
}
