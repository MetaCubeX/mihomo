package logic

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/common"
)

type Logic struct {
	common.Base
	payload  string
	adapter  string
	ruleType C.RuleType
	rules    []C.Rule
	subRules map[string][]C.Rule

	payloadOnce sync.Once
}

func NewSubRule(payload, adapter string, subRules map[string][]C.Rule, parseRule common.ParseRuleFunc) (*Logic, error) {
	logic := &Logic{Base: common.Base{}, payload: payload, adapter: adapter, ruleType: C.SubRules, subRules: subRules}
	err := logic.parsePayload(fmt.Sprintf("(%s)", payload), parseRule)
	if err != nil {
		return nil, err
	}

	if len(logic.rules) != 1 {
		return nil, fmt.Errorf("Sub-Rule rule must contain one rule")
	}
	return logic, nil
}

func NewNOT(payload string, adapter string, parseRule common.ParseRuleFunc) (*Logic, error) {
	logic := &Logic{Base: common.Base{}, payload: payload, adapter: adapter, ruleType: C.NOT}
	err := logic.parsePayload(payload, parseRule)
	if err != nil {
		return nil, err
	}

	if len(logic.rules) != 1 {
		return nil, fmt.Errorf("not rule must contain one rule")
	}
	return logic, nil
}

func NewOR(payload string, adapter string, parseRule common.ParseRuleFunc) (*Logic, error) {
	logic := &Logic{Base: common.Base{}, payload: payload, adapter: adapter, ruleType: C.OR}
	err := logic.parsePayload(payload, parseRule)
	if err != nil {
		return nil, err
	}
	return logic, nil
}

func NewAND(payload string, adapter string, parseRule common.ParseRuleFunc) (*Logic, error) {
	logic := &Logic{Base: common.Base{}, payload: payload, adapter: adapter, ruleType: C.AND}
	err := logic.parsePayload(payload, parseRule)
	if err != nil {
		return nil, err
	}
	return logic, nil
}

type Range struct {
	start int
	end   int
}

func (r Range) containRange(preStart, preEnd int) bool {
	return preStart < r.start && preEnd > r.end
}

func (logic *Logic) payloadToRule(subPayload string, parseRule common.ParseRuleFunc) (C.Rule, error) {
	tp, payload, target, param := common.ParseRulePayload(subPayload, false)
	switch tp {
	case "MATCH", "SUB-RULE":
		return nil, fmt.Errorf("unsupported rule type [%s] on logic rule", tp)
	case "":
		return nil, fmt.Errorf("[%s] format is error", subPayload)
	}
	return parseRule(tp, payload, target, param, nil)
}

func (logic *Logic) format(payload string) ([]Range, error) {
	stack := make([]int, 0)
	subRanges := make([]Range, 0)
	for i, c := range payload {
		if c == '(' {
			stack = append(stack, i) // push
		} else if c == ')' {
			if len(stack) == 0 {
				return nil, fmt.Errorf("missing '('")
			}

			back := len(stack) - 1
			start := stack[back] // back
			stack = stack[:back] // pop
			subRanges = append(subRanges, Range{
				start: start,
				end:   i,
			})
		}
	}

	if len(stack) != 0 {
		return nil, fmt.Errorf("format error is missing )")
	}

	sort.Slice(subRanges, func(i, j int) bool {
		return subRanges[i].start < subRanges[j].start
	})

	return subRanges, nil
}

func (logic *Logic) findSubRuleRange(payload string, ruleRanges []Range) []Range {
	payloadLen := len(payload)
	subRuleRange := make([]Range, 0)
	for _, rr := range ruleRanges {
		if rr.start == 0 && rr.end == payloadLen-1 {
			// 最大范围跳过
			continue
		}

		containInSub := false
		for _, r := range subRuleRange {
			if rr.containRange(r.start, r.end) {
				// The subRuleRange contains a range of rr, which is the next level node of the tree
				containInSub = true
				break
			}
		}

		if !containInSub {
			subRuleRange = append(subRuleRange, rr)
		}
	}

	return subRuleRange
}

func (logic *Logic) parsePayload(payload string, parseRule common.ParseRuleFunc) error {
	if !strings.HasPrefix(payload, "(") || !strings.HasSuffix(payload, ")") { // the payload must be "(xxx)" format
		return fmt.Errorf("payload format error")
	}

	subAllRanges, err := logic.format(payload)
	if err != nil {
		return err
	}

	rules := make([]C.Rule, 0, len(subAllRanges))

	subRanges := logic.findSubRuleRange(payload, subAllRanges)
	for _, subRange := range subRanges {
		subPayload := payload[subRange.start+1 : subRange.end]

		rule, err := logic.payloadToRule(subPayload, parseRule)
		if err != nil {
			return err
		}

		rules = append(rules, rule)
	}

	logic.rules = rules

	return nil
}

func (logic *Logic) RuleType() C.RuleType {
	return logic.ruleType
}

func matchSubRules(metadata *C.Metadata, name string, subRules map[string][]C.Rule, helper C.RuleMatchHelper) (bool, string) {
	for _, rule := range subRules[name] {
		if m, a := rule.Match(metadata, helper); m {
			if rule.RuleType() == C.SubRules {
				return matchSubRules(metadata, rule.Adapter(), subRules, helper)
			} else {
				return m, a
			}
		}
	}
	return false, ""
}

func (logic *Logic) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	switch logic.ruleType {
	case C.SubRules:
		if m, _ := logic.rules[0].Match(metadata, helper); m {
			return matchSubRules(metadata, logic.adapter, logic.subRules, helper)
		}
		return false, ""
	case C.NOT:
		if m, _ := logic.rules[0].Match(metadata, helper); !m {
			return true, logic.adapter
		}
		return false, ""
	case C.OR:
		for _, rule := range logic.rules {
			if m, _ := rule.Match(metadata, helper); m {
				return true, logic.adapter
			}
		}
		return false, ""
	case C.AND:
		for _, rule := range logic.rules {
			if m, _ := rule.Match(metadata, helper); !m {
				return false, logic.adapter
			}
		}
		return true, logic.adapter
	default:
		return false, ""
	}
}

func (logic *Logic) Adapter() string {
	return logic.adapter
}

func (logic *Logic) Payload() string {
	logic.payloadOnce.Do(func() { // a little bit expensive, so only computed once
		switch logic.ruleType {
		case C.NOT:
			logic.payload = fmt.Sprintf("(!(%s,%s))", logic.rules[0].RuleType(), logic.rules[0].Payload())
		case C.OR:
			payloads := make([]string, 0, len(logic.rules))
			for _, rule := range logic.rules {
				payloads = append(payloads, fmt.Sprintf("(%s,%s)", rule.RuleType().String(), rule.Payload()))
			}
			logic.payload = fmt.Sprintf("(%s)", strings.Join(payloads, " || "))
		case C.AND:
			payloads := make([]string, 0, len(logic.rules))
			for _, rule := range logic.rules {
				payloads = append(payloads, fmt.Sprintf("(%s,%s)", rule.RuleType().String(), rule.Payload()))
			}
			logic.payload = fmt.Sprintf("(%s)", strings.Join(payloads, " && "))
		default:
		}
	})
	return logic.payload
}

func (logic *Logic) ProviderNames() (names []string) {
	for _, rule := range logic.rules {
		names = append(names, rule.ProviderNames()...)
	}
	return
}

var _ C.Rule = (*Logic)(nil)
