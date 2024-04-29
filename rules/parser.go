package rules

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/rules/logic"
	RP "github.com/metacubex/mihomo/rules/provider"
)

func ParseRule(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, parseErr error) {
	switch tp {
	case "DOMAIN":
		parsed = RC.NewDomain(payload, target)
	case "DOMAIN-SUFFIX":
		parsed = RC.NewDomainSuffix(payload, target)
	case "DOMAIN-KEYWORD":
		parsed = RC.NewDomainKeyword(payload, target)
	case "DOMAIN-REGEX":
		parsed, parseErr = RC.NewDomainRegex(payload, target)
	case "GEOSITE":
		parsed, parseErr = RC.NewGEOSITE(payload, target)
	case "GEOIP":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewGEOIP(payload, target, false, noResolve)
	case "SRC-GEOIP":
		parsed, parseErr = RC.NewGEOIP(payload, target, true, true)
	case "IP-ASN":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewIPASN(payload, target, false, noResolve)
	case "SRC-IP-ASN":
		parsed, parseErr = RC.NewIPASN(payload, target, true, true)
	case "IP-CIDR", "IP-CIDR6":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewIPCIDR(payload, target, RC.WithIPCIDRNoResolve(noResolve))
	case "SRC-IP-CIDR":
		parsed, parseErr = RC.NewIPCIDR(payload, target, RC.WithIPCIDRSourceIP(true), RC.WithIPCIDRNoResolve(true))
	case "IP-SUFFIX":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewIPSuffix(payload, target, false, noResolve)
	case "SRC-IP-SUFFIX":
		parsed, parseErr = RC.NewIPSuffix(payload, target, true, true)
	case "SRC-PORT":
		parsed, parseErr = RC.NewPort(payload, target, C.SrcPort)
	case "DST-PORT":
		parsed, parseErr = RC.NewPort(payload, target, C.DstPort)
	case "IN-PORT":
		parsed, parseErr = RC.NewPort(payload, target, C.InPort)
	case "DSCP":
		parsed, parseErr = RC.NewDSCP(payload, target)
	case "PROCESS-NAME":
		parsed, parseErr = RC.NewProcess(payload, target, true)
	case "PROCESS-PATH":
		parsed, parseErr = RC.NewProcess(payload, target, false)
	case "NETWORK":
		parsed, parseErr = RC.NewNetworkType(payload, target)
	case "UID":
		parsed, parseErr = RC.NewUid(payload, target)
	case "IN-TYPE":
		parsed, parseErr = RC.NewInType(payload, target)
	case "IN-USER":
		parsed, parseErr = RC.NewInUser(payload, target)
	case "IN-NAME":
		parsed, parseErr = RC.NewInName(payload, target)
	case "SUB-RULE":
		parsed, parseErr = logic.NewSubRule(payload, target, subRules, ParseRule)
	case "AND":
		parsed, parseErr = logic.NewAND(payload, target, ParseRule)
	case "OR":
		parsed, parseErr = logic.NewOR(payload, target, ParseRule)
	case "NOT":
		parsed, parseErr = logic.NewNOT(payload, target, ParseRule)
	case "RULE-SET":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RP.NewRuleSet(payload, target, noResolve)
	case "MATCH":
		parsed = RC.NewMatch(target)
		parseErr = nil
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	if parseErr != nil {
		return nil, parseErr
	}

	return
}
