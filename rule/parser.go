package rules

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"
)

func ParseRule(tp, payload, target string, params []string) (C.Rule, error) {
	var (
		parseErr error
		parsed   C.Rule
	)

	ruleExtra := &C.RuleExtra{
		Network:   findNetwork(params),
		SourceIPs: findSourceIPs(params),
	}

	switch tp {
	case "DOMAIN":
		parsed = NewDomain(payload, target, ruleExtra)
	case "DOMAIN-SUFFIX":
		parsed = NewDomainSuffix(payload, target, ruleExtra)
	case "DOMAIN-KEYWORD":
		parsed = NewDomainKeyword(payload, target, ruleExtra)
	case "GEOSITE":
		parsed, parseErr = NewGEOSITE(payload, target, ruleExtra)
	case "GEOIP":
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewGEOIP(payload, target, noResolve, ruleExtra)
	case "IP-CIDR", "IP-CIDR6":
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewIPCIDR(payload, target, ruleExtra, WithIPCIDRNoResolve(noResolve))
	case "SRC-IP-CIDR":
		parsed, parseErr = NewIPCIDR(payload, target, ruleExtra, WithIPCIDRSourceIP(true), WithIPCIDRNoResolve(true))
	case "SRC-PORT":
		parsed, parseErr = NewPort(payload, target, true, ruleExtra)
	case "DST-PORT":
		parsed, parseErr = NewPort(payload, target, false, ruleExtra)
	case "PROCESS-NAME":
		parsed, parseErr = NewProcess(payload, target, ruleExtra)
	case "RULE-SET":
		parsed, parseErr = NewRuleSet(payload, target, ruleExtra)
	case "SCRIPT":
		parsed, parseErr = NewScript(payload, target)
	case "MATCH":
		parsed = NewMatch(target, ruleExtra)
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	return parsed, parseErr
}
