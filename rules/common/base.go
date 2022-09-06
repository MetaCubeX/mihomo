package common

import (
	"errors"
)

var (
	errPayload = errors.New("payloadRule error")
	initFlag   bool
	noResolve  = "no-resolve"
)

type Base struct {
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
