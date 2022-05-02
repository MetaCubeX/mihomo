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

	switch tp {
	case "DOMAIN":
		parsed = RC.NewDomain(payload, target)
	case "DOMAIN-SUFFIX":
		parsed = RC.NewDomainSuffix(payload, target)
	case "DOMAIN-KEYWORD":
		parsed = RC.NewDomainKeyword(payload, target)
	case "GEOSITE":
		parsed, parseErr = RC.NewGEOSITE(payload, target)
	case "GEOIP":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewGEOIP(payload, target, noResolve)
	case "IP-CIDR", "IP-CIDR6":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewIPCIDR(payload, target, RC.WithIPCIDRNoResolve(noResolve))
	case "SRC-IP-CIDR":
		parsed, parseErr = RC.NewIPCIDR(payload, target, RC.WithIPCIDRSourceIP(true), RC.WithIPCIDRNoResolve(true))
	case "SRC-PORT":
		parsed, parseErr = RC.NewPort(payload, target, true)
	case "DST-PORT":
		parsed, parseErr = RC.NewPort(payload, target, false)
	case "PROCESS-NAME":
		parsed, parseErr = RC.NewProcess(payload, target, true)
	case "PROCESS-PATH":
		parsed, parseErr = RC.NewProcess(payload, target, false)
	case "NETWORK":
		parsed, parseErr = RC.NewNetworkType(payload, target)
	case "UID":
		parsed, parseErr = RC.NewUid(payload, target)
	case "AND":
		parsed, parseErr = logic.NewAND(payload, target)
	case "OR":
		parsed, parseErr = logic.NewOR(payload, target)
	case "NOT":
		parsed, parseErr = logic.NewNOT(payload, target)
	case "RULE-SET":
		parsed, parseErr = RP.NewRuleSet(payload, target)
	case "MATCH":
		parsed = RC.NewMatch(target)
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	if parseErr != nil {
		return nil, parseErr
	}

	ruleExtra := &C.RuleExtra{
		Network:      RC.FindNetwork(params),
		SourceIPs:    RC.FindSourceIPs(params),
		ProcessNames: RC.FindProcessName(params),
	}

	parsed.SetRuleExtra(ruleExtra)

	return parsed, nil
}
