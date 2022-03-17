package logic

import (
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/rule/common"
)

type AND struct {
	common.Base
	rules   []C.Rule
	payload string
	adapter string
	needIP  bool
}

func (A *AND) ShouldFindProcess() bool {
	return false
}

func NewAND(payload string, adapter string) (*AND, error) {
	and := &AND{payload: payload, adapter: adapter}
	rules, err := parseRuleByPayload(payload)
	if err != nil {
		return nil, err
	}

	and.rules = rules
	for _, rule := range rules {
		if rule.ShouldResolveIP() {
			and.needIP = true
			break
		}
	}

	return and, nil
}

func (A *AND) RuleType() C.RuleType {
	return C.AND
}

func (A *AND) Match(metadata *C.Metadata) bool {
	for _, rule := range A.rules {
		if !rule.Match(metadata) {
			return false
		}
	}

	return true
}

func (A *AND) Adapter() string {
	return A.adapter
}

func (A *AND) Payload() string {
	return A.payload
}

func (A *AND) ShouldResolveIP() bool {
	return A.needIP
}
