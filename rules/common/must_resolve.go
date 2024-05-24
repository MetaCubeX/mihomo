package common

import (
	C "github.com/metacubex/mihomo/constant"
)

type MustResolve struct {
	adapter string
}

func (f *MustResolve) RuleType() C.RuleType {
	return C.MustResolve
}

func (f *MustResolve) Match(metadata *C.Metadata) (bool, string) {
	if metadata.DstIP.IsUnspecified() {
		return true, f.adapter
	}
	return false, f.adapter
}

func (f *MustResolve) Adapter() string {
	return f.adapter
}

func (f *MustResolve) Payload() string {
	return "MustResolve"
}

func (f *MustResolve) ShouldResolveIP() bool {
	return true
}

func (f *MustResolve) ShouldFindProcess() bool {
	return false
}

func NewMustResolve(adapter string) *MustResolve {
	return &MustResolve{
		adapter: adapter,
	}
}
