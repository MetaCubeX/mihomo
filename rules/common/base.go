package common

import (
	"errors"

	"golang.org/x/exp/slices"
)

var (
	errPayload = errors.New("payloadRule error")
	noResolve  = "no-resolve"
	src        = "src"
)

type Base struct {
}

func (b *Base) ShouldFindProcess() bool {
	return false
}

func (b *Base) ShouldResolveIP() bool {
	return false
}

func (b *Base) ProviderNames() []string { return nil }

func HasNoResolve(params []string) bool {
	return slices.Contains(params, noResolve)
}

func HasSrc(params []string) bool {
	return slices.Contains(params, src)
}
