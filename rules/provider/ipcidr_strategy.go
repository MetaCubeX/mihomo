package provider

import (
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type ipcidrStrategy struct {
	count           int
	shouldResolveIP bool
	trie            *trie.IpCidrTrie
}

func (i *ipcidrStrategy) ShouldFindProcess() bool {
	return false
}

func (i *ipcidrStrategy) Match(metadata *C.Metadata) bool {
	return i.trie != nil && i.trie.IsContain(metadata.DstIP.AsSlice())
}

func (i *ipcidrStrategy) Count() int {
	return i.count
}

func (i *ipcidrStrategy) ShouldResolveIP() bool {
	return i.shouldResolveIP
}

func (i *ipcidrStrategy) Reset() {
	i.trie = trie.NewIpCidrTrie()
	i.count = 0
	i.shouldResolveIP = false
}

func (i *ipcidrStrategy) Insert(rule string) {
	err := i.trie.AddIpCidrForString(rule)
	if err != nil {
		log.Warnln("invalid Ipcidr:[%s]", rule)
	} else {
		i.shouldResolveIP = true
		i.count++
	}
}

func (i *ipcidrStrategy) FinishInsert() {}

func NewIPCidrStrategy() *ipcidrStrategy {
	return &ipcidrStrategy{}
}
