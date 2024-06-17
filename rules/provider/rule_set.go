package provider

import (
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
)

type RuleSet struct {
	*common.Base
	ruleProviderName  string
	adapter           string
	noResolveIP       bool
	shouldFindProcess bool
}

func (rs *RuleSet) ShouldFindProcess() bool {
	if rs.shouldFindProcess {
		return true
	}
	if provider, ok := rs.getProvider(); ok {
		return provider.ShouldFindProcess()
	}
	return false
}

func (rs *RuleSet) RuleType() C.RuleType {
	return C.RuleSet
}

func (rs *RuleSet) Match(metadata *C.Metadata) (bool, string) {
	if provider, ok := rs.getProvider(); ok {
		return provider.Match(metadata), rs.adapter
	}
	return false, ""
}

func (rs *RuleSet) Adapter() string {
	return rs.adapter
}

func (rs *RuleSet) Payload() string {
	if provider, ok := rs.getProvider(); ok {
		return provider.Name()
	}
	return ""
}

func (rs *RuleSet) ShouldResolveIP() bool {
	if rs.noResolveIP {
		return false
	}
	if provider, ok := rs.getProvider(); ok {
		return provider.ShouldResolveIP()
	}
	return false
}

func (rs *RuleSet) ProviderNames() []string {
	return []string{rs.ruleProviderName}
}

func (rs *RuleSet) getProvider() (P.RuleProvider, bool) {
	pp, ok := tunnel.RuleProviders()[rs.ruleProviderName]
	return pp, ok
}

func NewRuleSet(ruleProviderName string, adapter string, noResolveIP bool) (*RuleSet, error) {
	rs := &RuleSet{
		Base:             &common.Base{},
		ruleProviderName: ruleProviderName,
		adapter:          adapter,
		noResolveIP:      noResolveIP,
	}
	return rs, nil
}
