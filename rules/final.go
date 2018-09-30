package rules

import (
	C "github.com/Dreamacro/clash/constant"
)

type Final struct {
	adapter string
}

func (f *Final) RuleType() C.RuleType {
	return C.FINAL
}

func (f *Final) IsMatch(metadata *C.Metadata) bool {
	return true
}

func (f *Final) Adapter() string {
	return f.adapter
}

func (f *Final) Payload() string {
	return ""
}

func NewFinal(adapter string) *Final {
	return &Final{
		adapter: adapter,
	}
}
