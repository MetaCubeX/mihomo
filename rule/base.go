package rules

import (
	"errors"

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
