package ruleparser

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	RC "github.com/Dreamacro/clash/rule/common"
)

func ParseSameRule(tp, payload, target string, params []string) (parsed C.Rule, parseErr error) {
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
	case "IP-SUFFIX":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewIPSuffix(payload, target, false, noResolve)
	case "SRC-IP-SUFFIX":
		parsed, parseErr = RC.NewIPSuffix(payload, target, true, true)
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
	case "IN-TYPE":
		parsed, parseErr = RC.NewInType(payload, target)
	default:
		parseErr = NewUnsupportedError(tp)
	}
	return
}

type UnsupportedError struct {
	err string
}

func (ue UnsupportedError) Error() string {
	return ue.err
}

func NewUnsupportedError(tp any) *UnsupportedError {
	return &UnsupportedError{err: fmt.Sprintf("unsupported rule type %s", tp)}
}

func IsUnsupported(err error) bool {
	_, ok := err.(*UnsupportedError)
	return ok
}
