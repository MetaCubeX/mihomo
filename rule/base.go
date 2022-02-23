package rules

import (
	"errors"
	"net"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

var (
	errPayload = errors.New("payload error")

	noResolve = "no-resolve"
)

func HasNoResolve(params []string) bool {
	for _, p := range params {
		if p == noResolve {
			return true
		}
	}
	return false
}

func findNetwork(params []string) C.NetWork {
	for _, p := range params {
		if strings.EqualFold(p, "tcp") {
			return C.TCP
		} else if strings.EqualFold(p, "udp") {
			return C.UDP
		}
	}
	return C.ALLNet
}

func findSourceIPs(params []string) []*net.IPNet {
	var ips []*net.IPNet
	for _, p := range params {
		if p == noResolve || len(p) < 7 {
			continue
		}
		_, ipnet, err := net.ParseCIDR(p)
		if err != nil {
			continue
		}
		ips = append(ips, ipnet)
	}

	if len(ips) > 0 {
		return ips
	}
	return nil
}

func findProcessName(params []string) []string {
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
