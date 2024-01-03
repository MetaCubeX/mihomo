package logic

import (
	"fmt"
	list "github.com/bahlo/generic-list-go"
	"regexp"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/common"
)

type Logic struct {
	*common.Base
	payload     string
	adapter     string
	ruleType    C.RuleType
	rules       []C.Rule
	subRules    map[string][]C.Rule
	needIP      bool
	needProcess bool
}

type ParseRuleFunc func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (C.Rule, error)

func NewSubRule(payload, adapter string, subRules map[string][]C.Rule, parseRule ParseRuleFunc) (*Logic, error) {
	logic := &Logic{Base: &common.Base{}, payload: payload, adapter: adapter, ruleType: C.SubRules}
	err := logic.parsePayload(fmt.Sprintf("(%s)", payload), parseRule)
	if err != nil {
		return nil, err
	}

	if len(logic.rules) != 1 {
		return nil, fmt.Errorf("Sub-Rule rule must contain one rule")
	}
	for _, rule := range subRules[adapter] {
		if rule.ShouldResolveIP() {
			logic.needIP = true
		}
		if rule.ShouldFindProcess() {
			logic.needProcess = true
		}
	}
	logic.subRules = subRules
	return logic, nil
}

func NewNOT(payload string, adapter string, parseRule ParseRuleFunc) (*Logic, error) {
	logic := &Logic{Base: &common.Base{}, payload: payload, adapter: adapter, ruleType: C.NOT}
	err := logic.parsePayload(payload, parseRule)
	if err != nil {
		return nil, err
	}

	if len(logic.rules) != 1 {
		return nil, fmt.Errorf("not rule must contain one rule")
	}
	logic.needIP = logic.rules[0].ShouldResolveIP()
	logic.needProcess = logic.rules[0].ShouldFindProcess()
	logic.payload = fmt.Sprintf("(!(%s,%s))", logic.rules[0].RuleType(), logic.rules[0].Payload())
	return logic, nil
}

func NewOR(payload string, adapter string, parseRule ParseRuleFunc) (*Logic, error) {
	logic := &Logic{Base: &common.Base{}, payload: payload, adapter: adapter, ruleType: C.OR}
	err := logic.parsePayload(payload, parseRule)
	if err != nil {
		return nil, err
	}

	payloads := make([]string, 0, len(logic.rules))
	for _, rule := range logic.rules {
		payloads = append(payloads, fmt.Sprintf("(%s,%s)", rule.RuleType().String(), rule.Payload()))
		if rule.ShouldResolveIP() {
			logic.needIP = true
		}
		if rule.ShouldFindProcess() {
			logic.needProcess = true
		}
	}
	logic.payload = fmt.Sprintf("(%s)", strings.Join(payloads, " || "))

	return logic, nil
}
func NewAND(payload string, adapter string, parseRule ParseRuleFunc) (*Logic, error) {
	logic := &Logic{Base: &common.Base{}, payload: payload, adapter: adapter, ruleType: C.AND}
	err := logic.parsePayload(payload, parseRule)
	if err != nil {
		return nil, err
	}

	payloads := make([]string, 0, len(logic.rules))
	for _, rule := range logic.rules {
		payloads = append(payloads, fmt.Sprintf("(%s,%s)", rule.RuleType().String(), rule.Payload()))
		if rule.ShouldResolveIP() {
			logic.needIP = true
		}
		if rule.ShouldFindProcess() {
			logic.needProcess = true
		}
	}
	logic.payload = fmt.Sprintf("(%s)", strings.Join(payloads, " && "))

	return logic, nil
}

type Range struct {
	start int
	end   int
	index int
}

func (r Range) containRange(preStart, preEnd int) bool {
	return preStart < r.start && preEnd > r.end
}

func (logic *Logic) payloadToRule(subPayload string, parseRule ParseRuleFunc) (C.Rule, error) {
	splitStr := strings.SplitN(subPayload, ",", 2)
	if len(splitStr) < 2 {
		return nil, fmt.Errorf("[%s] format is error", subPayload)
	}

	tp := splitStr[0]
	payload := splitStr[1]
	switch tp {
	case "MATCH", "SUB-RULE":
		return nil, fmt.Errorf("unsupported rule type [%s] on logic rule", tp)
	case "NOT", "OR", "AND":
		return parseRule(tp, payload, "", nil, nil)
	}
	param := strings.Split(payload, ",")
	return parseRule(tp, param[0], "", param[1:], nil)
}

func (logic *Logic) format(payload string) ([]Range, error) {
	stack := list.New[Range]()
	num := 0
	subRanges := make([]Range, 0)
	for i, c := range payload {
		if c == '(' {
			sr := Range{
				start: i,
				index: num,
			}

			num++
			stack.PushBack(sr)
		} else if c == ')' {
			if stack.Len() == 0 {
				return nil, fmt.Errorf("missing '('")
			}

			sr := stack.Back()
			stack.Remove(sr)
			sr.Value.end = i
			subRanges = append(subRanges, sr.Value)
		}
	}

	if stack.Len() != 0 {
		return nil, fmt.Errorf("format error is missing )")
	}

	sortResult := make([]Range, len(subRanges))
	for _, sr := range subRanges {
		sortResult[sr.index] = sr
	}

	return sortResult, nil
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

func (logic *Logic) parsePayload(payload string, parseRule ParseRuleFunc) error {
	regex, err := regexp.Compile("\\(.*\\)")
	if err != nil {
		return err
	}

	if regex.MatchString(payload) {
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

	return fmt.Errorf("payload format error")
}

func (logic *Logic) RuleType() C.RuleType {
	return logic.ruleType
}

func matchSubRules(metadata *C.Metadata, name string, subRules map[string][]C.Rule) (bool, string) {
	for _, rule := range subRules[name] {
		if m, a := rule.Match(metadata); m {
			if rule.RuleType() == C.SubRules {
				matchSubRules(metadata, rule.Adapter(), subRules)
			} else {
				return m, a
			}
		}
	}
	return false, ""
}

func (logic *Logic) Match(metadata *C.Metadata) (bool, string) {
	switch logic.ruleType {
	case C.SubRules:
		if m, _ := logic.rules[0].Match(metadata); m {
			return matchSubRules(metadata, logic.adapter, logic.subRules)
		}
		return false, ""
	case C.NOT:
		if m, _ := logic.rules[0].Match(metadata); !m {
			return true, logic.adapter
		}
		return false, ""
	case C.OR:
		for _, rule := range logic.rules {
			if m, _ := rule.Match(metadata); m {
				return true, logic.adapter
			}
		}
		return false, ""
	case C.AND:
		for _, rule := range logic.rules {
			if m, _ := rule.Match(metadata); !m {
				return false, logic.adapter
			}
		}
		return true, logic.adapter
	}

	return false, ""
}

func (logic *Logic) Adapter() string {
	return logic.adapter
}

func (logic *Logic) Payload() string {
	return logic.payload
}

func (logic *Logic) ShouldResolveIP() bool {
	return logic.needIP
}

func (logic *Logic) ShouldFindProcess() bool {
	return logic.needProcess
}
