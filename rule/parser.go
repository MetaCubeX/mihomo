package rules

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"
)

func ParseRule(tp, payload, target string, params []string) (C.Rule, error) {
	var (
		parseErr error
		parsed   C.Rule
		network  = findNetwork(params)
	)

	switch tp {
	case "DOMAIN":
		parsed = NewDomain(payload, target, network)
	case "DOMAIN-SUFFIX":
		parsed = NewDomainSuffix(payload, target, network)
	case "DOMAIN-KEYWORD":
		parsed = NewDomainKeyword(payload, target, network)
	case "GEOSITE":
		parsed, parseErr = NewGEOSITE(payload, target, network)
	case "GEOIP":
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewGEOIP(payload, target, noResolve, network)
	case "IP-CIDR", "IP-CIDR6":
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewIPCIDR(payload, target, network, WithIPCIDRNoResolve(noResolve))
	case "SRC-IP-CIDR":
		parsed, parseErr = NewIPCIDR(payload, target, network, WithIPCIDRSourceIP(true), WithIPCIDRNoResolve(true))
	case "SRC-PORT":
		parsed, parseErr = NewPort(payload, target, true, network)
	case "DST-PORT":
		parsed, parseErr = NewPort(payload, target, false, network)
	case "PROCESS-NAME":
		parsed, parseErr = NewProcess(payload, target, network)
	case "MATCH":
		parsed = NewMatch(target)
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	return parsed, parseErr
}
