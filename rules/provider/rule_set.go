package provider

import (
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
)

type RuleSet struct {
	common.Base
	ruleProviderName string
	adapter          string
	isSrc            bool
	noResolveIP      bool
}

func (rs *RuleSet) RuleType() C.RuleType {
	return C.RuleSet
}

func (rs *RuleSet) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if provider, ok := rs.getProvider(); ok {
		if rs.isSrc {
			metadata.SwapSrcDst()
			defer metadata.SwapSrcDst()

			helper.ResolveIP = nil // src mode should not resolve ip
		} else if rs.noResolveIP {
			helper.ResolveIP = nil
		}
		return provider.Match(metadata, helper), rs.adapter
	}
	return false, ""
}

// MatchDomain implements C.DomainMatcher
func (rs *RuleSet) MatchDomain(domain string) bool {
	ok, _ := rs.Match(&C.Metadata{Host: domain}, C.RuleMatchHelper{})
	return ok
}

// MatchIp implements C.IpMatcher
func (rs *RuleSet) MatchIp(ip netip.Addr) bool {
	ok, _ := rs.Match(&C.Metadata{DstIP: ip}, C.RuleMatchHelper{})
	return ok
}

func (rs *RuleSet) Adapter() string {
	return rs.adapter
}

func (rs *RuleSet) Payload() string {
	return rs.ruleProviderName
}

func (rs *RuleSet) ProviderNames() []string {
	return []string{rs.ruleProviderName}
}

func (rs *RuleSet) getProvider() (P.RuleProvider, bool) {
	pp, ok := tunnel.RuleProviders()[rs.ruleProviderName]
	return pp, ok
}

func NewRuleSet(ruleProviderName string, adapter string, isSrc bool, noResolveIP bool) (*RuleSet, error) {
	rs := &RuleSet{
		Base:             common.Base{},
		ruleProviderName: ruleProviderName,
		adapter:          adapter,
		isSrc:            isSrc,
		noResolveIP:      noResolveIP,
	}
	return rs, nil
}

var _ C.Rule = (*RuleSet)(nil)
