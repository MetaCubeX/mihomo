package logic

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/rules/common"
	"strings"
)

type AND struct {
	*common.Base
	rules   []C.Rule
	payload string
	adapter string
	needIP  bool
}

func (A *AND) ShouldFindProcess() bool {
	return false
}

func NewAND(payload string, adapter string,
	parse func(tp, payload, target string, params []string) (parsed C.Rule, parseErr error)) (*AND, error) {
	and := &AND{Base: &common.Base{}, payload: payload, adapter: adapter}
	rules, err := parseRuleByPayload(payload, parse)
	if err != nil {
		return nil, err
	}

	and.rules = rules
	payloads := make([]string, 0, len(rules))
	for _, rule := range rules {
		payloads = append(payloads, fmt.Sprintf("(%s,%s)", rule.RuleType().String(), rule.Payload()))
		if rule.ShouldResolveIP() {
			and.needIP = true
			break
		}
	}

	and.payload = fmt.Sprintf("(%s)", strings.Join(payloads, " && "))
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
