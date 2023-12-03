package common

import (
	C "github.com/metacubex/mihomo/constant"
)

type Match struct {
	*Base
	adapter string
}

func (f *Match) RuleType() C.RuleType {
	return C.MATCH
}

func (f *Match) Match(metadata *C.Metadata) (bool, string) {
	return true, f.adapter
}

func (f *Match) Adapter() string {
	return f.adapter
}

func (f *Match) Payload() string {
	return ""
}

func NewMatch(adapter string) *Match {
	return &Match{
		Base:    &Base{},
		adapter: adapter,
	}
}

//var _ C.Rule = (*Match)(nil)
