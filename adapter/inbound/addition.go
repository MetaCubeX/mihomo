package inbound

import (
	C "github.com/Dreamacro/clash/constant"
)

type Addition struct {
	InName       string
	SpecialRules string
}

func (a Addition) Apply(metadata *C.Metadata) {
	metadata.InName = a.InName
	metadata.SpecialRules = a.SpecialRules
}
