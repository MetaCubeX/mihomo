package logic

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/rules/common"
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

func NewNOT(payload string, adapter string, parse func(tp, payload, target string, params []string, subRules *map[string][]C.Rule) (parsed C.Rule, parseErr error)) (*NOT, error) {
	not := &NOT{Base: &common.Base{}, adapter: adapter}
	rule, err := ParseRuleByPayload(payload, parse)
	if err != nil {
		return nil, err
	}

	if len(rule) != 1 {
		return nil, fmt.Errorf("not rule must contain one rule")
	}

	not.rule = rule[0]
	not.payload = fmt.Sprintf("(!(%s,%s))", rule[0].RuleType(), rule[0].Payload())

	return not, nil
}

func (not *NOT) RuleType() C.RuleType {
	return C.NOT
}

func (not *NOT) Match(metadata *C.Metadata) (bool, string) {
	if not.rule == nil {
		return true, not.adapter
	}

	if m, _ := not.rule.Match(metadata); !m {
		return true, not.adapter
	}

	return false, ""
}

func (not *NOT) Adapter() string {
	return not.adapter
}

func (not *NOT) Payload() string {
	return not.payload
}

func (not *NOT) ShouldResolveIP() bool {
	return not.rule != nil && not.rule.ShouldResolveIP()
}
