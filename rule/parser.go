package rules

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	RC "github.com/Dreamacro/clash/rule/common"
	"github.com/Dreamacro/clash/rule/logic"
	RP "github.com/Dreamacro/clash/rule/provider"
)

func ParseRule(tp, payload, target string, params []string) (C.Rule, error) {
	var (
		parseErr error
		parsed   C.Rule
	)

	ruleExtra := &C.RuleExtra{
		Network:      RC.FindNetwork(params),
		SourceIPs:    RC.FindSourceIPs(params),
		ProcessNames: RC.FindProcessName(params),
	}

	switch tp {
	case "DOMAIN":
		parsed = RC.NewDomain(payload, target, ruleExtra)
	case "DOMAIN-SUFFIX":
		parsed = RC.NewDomainSuffix(payload, target, ruleExtra)
	case "DOMAIN-KEYWORD":
		parsed = RC.NewDomainKeyword(payload, target, ruleExtra)
	case "GEOSITE":
		parsed, parseErr = RC.NewGEOSITE(payload, target, ruleExtra)
	case "GEOIP":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewGEOIP(payload, target, noResolve, ruleExtra)
	case "IP-CIDR", "IP-CIDR6":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewIPCIDR(payload, target, ruleExtra, RC.WithIPCIDRNoResolve(noResolve))
	case "SRC-IP-CIDR":
		parsed, parseErr = RC.NewIPCIDR(payload, target, ruleExtra, RC.WithIPCIDRSourceIP(true), RC.WithIPCIDRNoResolve(true))
	case "SRC-PORT":
		parsed, parseErr = RC.NewPort(payload, target, true, ruleExtra)
	case "DST-PORT":
		parsed, parseErr = RC.NewPort(payload, target, false, ruleExtra)
	case "PROCESS-NAME":
		parsed, parseErr = RC.NewProcess(payload, target, true,ruleExtra)
	case "PROCESS-PATH":
		parsed, parseErr = RC.NewProcess(payload, target, false,ruleExtra)
	case "MATCH":
		parsed = RC.NewMatch(target, ruleExtra)
	case "RULE-SET":
		parsed, parseErr = RP.NewRuleSet(payload, target, ruleExtra)
	case "NETWORK":
		parsed, parseErr = RC.NewNetworkType(payload, target)
	case "AND":
		parsed, parseErr = logic.NewAND(payload, target)
	case "OR":
		parsed, parseErr = logic.NewOR(payload, target)
	case "NOT":
		parsed, parseErr = logic.NewNOT(payload, target)
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	return parsed, parseErr
}
