package inbound

import (
	C "github.com/Dreamacro/clash/constant"
)

type Addition func(metadata *C.Metadata)

func (a Addition) Apply(metadata *C.Metadata) {
	a(metadata)
}

func WithInName(name string) Addition {
	return func(metadata *C.Metadata) {
		metadata.InName = name
	}
}

func WithSpecialRules(specialRules string) Addition {
	return func(metadata *C.Metadata) {
		metadata.SpecialRules = specialRules
	}
}

func WithSpecialProxy(specialProxy string) Addition {
	return func(metadata *C.Metadata) {
		metadata.SpecialProxy = specialProxy
	}
}
