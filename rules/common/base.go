package common

import (
	"errors"
)

var errPayload = errors.New("payloadRule error")
var NoResolve = "no-resolve"

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
		if p == NoResolve {
			return true
		}
	}
	return false
}
