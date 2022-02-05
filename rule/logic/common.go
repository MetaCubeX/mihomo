package logic

import (
	"fmt"
	"github.com/Dreamacro/clash/common/collections"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	RC "github.com/Dreamacro/clash/rule/common"
	"github.com/Dreamacro/clash/rule/provider"
	"regexp"
	"strings"
)

func parseRuleByPayload(payload string) ([]C.Rule, error) {
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

			rule, err := payloadToRule(subPayload)
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

func payloadToRule(subPayload string) (C.Rule, error) {
	splitStr := strings.SplitN(subPayload, ",", 2)
	tp := splitStr[0]
	payload := splitStr[1]
	if tp == "NOT" || tp == "OR" || tp == "AND" {
		return parseRule(tp, payload, nil)
	}
	if tp == "GEOSITE" {
		if err := config.InitGeoSite(); err != nil {
			log.Errorln("can't initial GeoSite: %w", err)
		}
	}

	param := strings.Split(payload, ",")
	return parseRule(tp, param[0], param[1:])
}

func parseRule(tp, payload string, params []string) (C.Rule, error) {
	var (
		parseErr error
		parsed   C.Rule
	)

	switch tp {
	case "DOMAIN":
		parsed = RC.NewDomain(payload, "", nil)
	case "DOMAIN-SUFFIX":
		parsed = RC.NewDomainSuffix(payload, "", nil)
	case "DOMAIN-KEYWORD":
		parsed = RC.NewDomainKeyword(payload, "", nil)
	case "GEOSITE":
		parsed, parseErr = RC.NewGEOSITE(payload, "", nil)
	case "GEOIP":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewGEOIP(payload, "", noResolve, nil)
	case "IP-CIDR", "IP-CIDR6":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewIPCIDR(payload, "", nil, RC.WithIPCIDRNoResolve(noResolve))
	case "SRC-IP-CIDR":
		parsed, parseErr = RC.NewIPCIDR(payload, "", nil, RC.WithIPCIDRSourceIP(true), RC.WithIPCIDRNoResolve(true))
	case "SRC-PORT":
		parsed, parseErr = RC.NewPort(payload, "", true, nil)
	case "DST-PORT":
		parsed, parseErr = RC.NewPort(payload, "", false, nil)
	case "PROCESS-NAME":
		parsed, parseErr = RC.NewProcess(payload, "", nil)
	case "RULE-SET":
		parsed, parseErr = provider.NewRuleSet(payload, "", nil)
	case "NOT":
		parsed, parseErr = NewNOT(payload, "")
	case "AND":
		parsed, parseErr = NewAND(payload, "")
	case "OR":
		parsed, parseErr = NewOR(payload, "")
	case "NETWORK":
		parsed, parseErr = RC.NewNetworkType(payload, "")
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	return parsed, parseErr
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
