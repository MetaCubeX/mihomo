package rules

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	P "github.com/Dreamacro/clash/constant/provider"
)

type RuleSet struct {
	ruleProviderName string
	adapter          string
	ruleProvider     P.RuleProvider
	ruleExtra        *C.RuleExtra
}

func (rs *RuleSet) RuleType() C.RuleType {
	return C.RuleSet
}

func (rs *RuleSet) Match(metadata *C.Metadata) bool {
	return rs.getProviders().Match(metadata)
}

func (rs *RuleSet) Adapter() string {
	return rs.adapter
}

func (rs *RuleSet) Payload() string {
	return rs.getProviders().Name()
}

func (rs *RuleSet) ShouldResolveIP() bool {
	return rs.getProviders().ShouldResolveIP()
}
func (rs *RuleSet) getProviders() P.RuleProvider {
	if rs.ruleProvider == nil {
		rp := RuleProviders()[rs.ruleProviderName]
		rs.ruleProvider = rp
	}

	return rs.ruleProvider
}

func (rs *RuleSet) RuleExtra() *C.RuleExtra {
	return nil
}

func NewRuleSet(ruleProviderName string, adapter string, ruleExtra *C.RuleExtra) (*RuleSet, error) {
	rp, ok := RuleProviders()[ruleProviderName]
	if !ok {
		return nil, fmt.Errorf("rule set %s not found", ruleProviderName)
	}
	return &RuleSet{
		ruleProviderName: ruleProviderName,
		adapter:          adapter,
		ruleProvider:     rp,
		ruleExtra:        ruleExtra,
	}, nil
}
