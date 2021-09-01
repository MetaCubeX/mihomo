package rules

import (
	C "github.com/Dreamacro/clash/constant"
)

type Match struct {
	adapter   string
	ruleExtra *C.RuleExtra
}

func (f *Match) RuleType() C.RuleType {
	return C.MATCH
}

func (f *Match) Match(metadata *C.Metadata) bool {
	return true
}

func (f *Match) Adapter() string {
	return f.adapter
}

func (f *Match) Payload() string {
	return ""
}

func (f *Match) ShouldResolveIP() bool {
	return false
}

func (f *Match) RuleExtra() *C.RuleExtra {
	return f.ruleExtra
}

func NewMatch(adapter string, ruleExtra *C.RuleExtra) *Match {
	if ruleExtra.SourceIPs == nil {
		ruleExtra = nil
	}
	return &Match{
		adapter:   adapter,
		ruleExtra: ruleExtra,
	}
}
