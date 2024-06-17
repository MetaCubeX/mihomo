package provider

import (
	"github.com/metacubex/mihomo/component/cidr"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"go4.org/netipx"
)

type ipcidrStrategy struct {
	count           int
	shouldResolveIP bool
	cidrSet         *cidr.IpCidrSet
	//trie            *trie.IpCidrTrie
}

func (i *ipcidrStrategy) ShouldFindProcess() bool {
	return false
}

func (i *ipcidrStrategy) Match(metadata *C.Metadata) bool {
	// return i.trie != nil && i.trie.IsContain(metadata.DstIP.AsSlice())
	return i.cidrSet != nil && i.cidrSet.IsContain(metadata.DstIP)
}

func (i *ipcidrStrategy) Count() int {
	return i.count
}

func (i *ipcidrStrategy) ShouldResolveIP() bool {
	return i.shouldResolveIP
}

func (i *ipcidrStrategy) Reset() {
	// i.trie = trie.NewIpCidrTrie()
	i.cidrSet = cidr.NewIpCidrSet()
	i.count = 0
	i.shouldResolveIP = false
}

func (i *ipcidrStrategy) Insert(rule string) {
	//err := i.trie.AddIpCidrForString(rule)
	err := i.cidrSet.AddIpCidrForString(rule)
	if err != nil {
		log.Warnln("invalid Ipcidr:[%s]", rule)
	} else {
		i.shouldResolveIP = true
		i.count++
	}
}

func (i *ipcidrStrategy) FinishInsert() {
	i.cidrSet.Merge()
}

func (i *ipcidrStrategy) ToIpCidr() *netipx.IPSet {
	return i.cidrSet.ToIPSet()
}

func NewIPCidrStrategy() *ipcidrStrategy {
	return &ipcidrStrategy{}
}
