package provider

import (
	"github.com/metacubex/mihomo/component/cidr"
	C "github.com/metacubex/mihomo/constant"
)

type IpCidrSet struct {
	*ipcidrStrategy
	adapter string
}

func (d *IpCidrSet) ProviderNames() []string {
	return nil
}

func (d *IpCidrSet) RuleType() C.RuleType {
	return C.IpCidrSet
}

func (d *IpCidrSet) Match(metadata *C.Metadata) (bool, string) {
	return d.ipcidrStrategy.Match(metadata), d.adapter
}

func (d *IpCidrSet) Adapter() string {
	return d.adapter
}

func (d *IpCidrSet) Payload() string {
	return ""
}

func NewIpCidrSet(cidrSet *cidr.IpCidrSet, adapter string) *IpCidrSet {
	return &IpCidrSet{
		ipcidrStrategy: &ipcidrStrategy{cidrSet: cidrSet},
		adapter:        adapter,
	}
}

var _ C.Rule = (*IpCidrSet)(nil)
