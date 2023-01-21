package provider

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	P "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/rules/common"
)

type RuleSet struct {
	*common.Base
	ruleProviderName  string
	adapter           string
	ruleProvider      P.RuleProvider
	noResolveIP       bool
	shouldFindProcess bool
}

func (rs *RuleSet) ShouldFindProcess() bool {
	return rs.shouldFindProcess || rs.getProviders().ShouldFindProcess()
}

func (rs *RuleSet) RuleType() C.RuleType {
	return C.RuleSet
}

func (rs *RuleSet) Match(metadata *C.Metadata) (bool, string) {
	return rs.getProviders().Match(metadata), rs.adapter
}

func (rs *RuleSet) Adapter() string {
	return rs.adapter
}

func (rs *RuleSet) Payload() string {
	return rs.getProviders().Name()
}

func (rs *RuleSet) ShouldResolveIP() bool {
	return !rs.noResolveIP && rs.getProviders().ShouldResolveIP()
}
func (rs *RuleSet) getProviders() P.RuleProvider {
	if rs.ruleProvider == nil {
		rp := RuleProviders()[rs.ruleProviderName]
		rs.ruleProvider = rp
	}

	return rs.ruleProvider
}

func NewRuleSet(ruleProviderName string, adapter string, noResolveIP bool) (*RuleSet, error) {
	rp, ok := RuleProviders()[ruleProviderName]
	if !ok {
		return nil, fmt.Errorf("rule set %s not found", ruleProviderName)
	}
	return &RuleSet{
		Base:             &common.Base{},
		ruleProviderName: ruleProviderName,
		adapter:          adapter,
		ruleProvider:     rp,
		noResolveIP:      noResolveIP,
	}, nil
}
