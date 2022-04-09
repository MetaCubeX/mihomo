package logic

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/rule/common"
)

type NOT struct {
	*common.Base
	rule    C.Rule
	payload string
	adapter string
}

func (not *NOT) ShouldFindProcess() bool {
	return false
}

func NewNOT(payload string, adapter string) (*NOT, error) {
	not := &NOT{Base: &common.Base{}, payload: payload, adapter: adapter}
	rule, err := parseRuleByPayload(payload, false)
	if err != nil {
		return nil, err
	}

	if len(rule) < 1 {
		return nil, fmt.Errorf("NOT rule have not a rule")
	}

	not.rule = rule[0]
	return not, nil
}

func (not *NOT) RuleType() C.RuleType {
	return C.NOT
}

func (not *NOT) Match(metadata *C.Metadata) bool {
	return !not.rule.Match(metadata)
}

func (not *NOT) Adapter() string {
	return not.adapter
}

func (not *NOT) Payload() string {
	return not.payload
}

func (not *NOT) ShouldResolveIP() bool {
	return not.rule.ShouldResolveIP()
}
