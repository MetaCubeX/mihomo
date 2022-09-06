package logic

import (
	"fmt"
	"github.com/Dreamacro/clash/common/collections"
	C "github.com/Dreamacro/clash/constant"
	"regexp"
	"strings"
	_ "unsafe"
)

func ParseRuleByPayload(payload string, parseRule func(tp, payload, target string, params []string, subRules *map[string][]C.Rule) (parsed C.Rule, parseErr error)) ([]C.Rule, error) {
	regex, err := regexp.Compile("\\(.*\\)")
	if err != nil {
		return nil, err
	}

	if regex.MatchString(payload) {
		subAllRanges, err := format(payload)
		if err != nil {
			return nil, err
		}
		rules := make([]C.Rule, 0, len(subAllRanges))

		subRanges := findSubRuleRange(payload, subAllRanges)
		for _, subRange := range subRanges {
			subPayload := payload[subRange.start+1 : subRange.end]

			rule, err := payloadToRule(subPayload, parseLogicSubRule(parseRule))
			if err != nil {
				return nil, err
			}

			rules = append(rules, rule)
		}

		return rules, nil
	}

	return nil, fmt.Errorf("payload format error")
}

func containRange(r Range, preStart, preEnd int) bool {
	return preStart < r.start && preEnd > r.end
}

func payloadToRule(subPayload string, parseRule func(tp, payload, target string, params []string) (parsed C.Rule, parseErr error)) (C.Rule, error) {
	splitStr := strings.SplitN(subPayload, ",", 2)
	if len(splitStr) < 2 {
		return nil, fmt.Errorf("[%s] format is error", subPayload)
	}

	tp := splitStr[0]
	payload := splitStr[1]
	if tp == "NOT" || tp == "OR" || tp == "AND" {
		return parseRule(tp, payload, "", nil)
	}
	param := strings.Split(payload, ",")
	return parseRule(tp, param[0], "", param[1:])
}

func parseLogicSubRule(parseRule func(tp, payload, target string, params []string, subRules *map[string][]C.Rule) (parsed C.Rule, parseErr error)) func(tp, payload, target string, params []string) (parsed C.Rule, parseErr error) {
	return func(tp, payload, target string, params []string) (parsed C.Rule, parseErr error) {
		switch tp {
		case "MATCH", "SUB-RULE":
			return nil, fmt.Errorf("unsupported rule type [%s] on logic rule", tp)
		default:
			return parseRule(tp, payload, target, params, nil)
		}
	}
}

type Range struct {
	start int
	end   int
	index int
}

func format(payload string) ([]Range, error) {
	stack := collections.NewStack()
	num := 0
	subRanges := make([]Range, 0)
	for i, c := range payload {
		if c == '(' {
			sr := Range{
				start: i,
				index: num,
			}

			num++
			stack.Push(sr)
		} else if c == ')' {
			if stack.Len() == 0 {
				return nil, fmt.Errorf("missing '('")
			}

			sr := stack.Pop().(Range)
			sr.end = i
			subRanges = append(subRanges, sr)
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

func findSubRuleRange(payload string, ruleRanges []Range) []Range {
	payloadLen := len(payload)
	subRuleRange := make([]Range, 0)
	for _, rr := range ruleRanges {
		if rr.start == 0 && rr.end == payloadLen-1 {
			// 最大范围跳过
			continue
		}

		containInSub := false
		for _, r := range subRuleRange {
			if containRange(rr, r.start, r.end) {
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
