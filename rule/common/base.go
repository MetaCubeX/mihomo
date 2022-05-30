package common

import (
	"errors"
	"net/netip"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

var (
	errPayload = errors.New("payload error")
	initFlag   bool
	noResolve  = "no-resolve"
)

type Base struct {
	ruleExtra *C.RuleExtra
}

func (b *Base) RuleExtra() *C.RuleExtra {
	return b.ruleExtra
}

func (b *Base) SetRuleExtra(re *C.RuleExtra) {
	b.ruleExtra = re
}

func (b *Base) ShouldFindProcess() bool {
	return false
}

func (b *Base) ShouldResolveIP() bool {
	return false
}

func HasNoResolve(params []string) bool {
	for _, p := range params {
		if p == noResolve {
			return true
		}
	}
	return false
}

func FindNetwork(params []string) C.NetWork {
	for _, p := range params {
		if strings.EqualFold(p, "tcp") {
			return C.TCP
		} else if strings.EqualFold(p, "udp") {
			return C.UDP
		}
	}
	return C.ALLNet
}

func FindSourceIPs(params []string) []*netip.Prefix {
	var ips []*netip.Prefix
	for _, p := range params {
		if p == noResolve || len(p) < 7 {
			continue
		}
		ipnet, err := netip.ParsePrefix(p)
		if err != nil {
			continue
		}
		ips = append(ips, &ipnet)
	}

	if len(ips) > 0 {
		return ips
	}
	return nil
}

func FindProcessName(params []string) []string {
	var processNames []string
	for _, p := range params {
		if strings.HasPrefix(p, "P:") {
			processNames = append(processNames, strings.TrimPrefix(p, "P:"))
		}
	}

	if len(processNames) > 0 {
		return processNames
	}
	return nil
}
