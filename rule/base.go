package rules

import (
	"errors"
	"net"

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
		if p == "tcp" {
			return C.TCP
		} else if p == "udp" {
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
