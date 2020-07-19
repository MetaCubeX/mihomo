package rules

import (
	"errors"
)

var (
	errPayload            = errors.New("payload error")
	errParams             = errors.New("params error")
	ErrPlatformNotSupport = errors.New("not support on this platform")

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
