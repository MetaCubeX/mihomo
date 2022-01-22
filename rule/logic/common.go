package logic

import (
	"fmt"
	"github.com/Dreamacro/clash/common/collections"
	C "github.com/Dreamacro/clash/constant"
	RC "github.com/Dreamacro/clash/rule/common"
	"github.com/Dreamacro/clash/rule/provider"
	"regexp"
	"strings"
)

func parseRule(payload string) ([]C.Rule, error) {
	regex, err := regexp.Compile("\\(.*\\)")
	if err != nil {
		return nil, err
	}

	if regex.MatchString(payload) {
		subRanges, err := format(payload)
		if err != nil {
			return nil, err
		}
		rules := make([]C.Rule, 0, len(subRanges))

		if len(subRanges) == 1 {
			subPayload := payload[subRanges[0].start+1 : subRanges[0].end-1]
			rule, err := payloadToRule(subPayload)
			if err != nil {
				return nil, err
			}

			rules = append(rules, rule)
		} else {
			preStart := subRanges[0].start
			preEnd := subRanges[0].end
			for _, sr := range subRanges[1:] {
				if containRange(sr, preStart, preEnd) && sr.start-preStart > 1 {
					str := ""
					if preStart+1 <= sr.start-1 {
						str = strings.TrimSpace(payload[preStart+1 : sr.start-1])
					}

					if str == "AND" || str == "OR" || str == "NOT" {
						subPayload := payload[preStart+1 : preEnd]
						rule, err := payloadToRule(subPayload)
						if err != nil {
							return nil, err
						}

						rules = append(rules, rule)
						preStart = sr.start
						preEnd = sr.end
					}

					continue
				}

				preStart = sr.start
				preEnd = sr.end

				subPayload := payload[sr.start+1 : sr.end]
				rule, err := payloadToRule(subPayload)
				if err != nil {
					return nil, err
				}

				rules = append(rules, rule)
			}
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
		return parseSubRule(tp, payload, nil)
	}

	param := strings.Split(payload, ",")
	return parseSubRule(tp, param[0], param[1:])
}

func splitSubRule(subRuleStr string) (string, string, []string, error) {
	typeAndRule := strings.Split(subRuleStr, ",")
	if len(typeAndRule) < 2 {
		return "", "", nil, fmt.Errorf("format error:[%s]", typeAndRule)
	}

	return strings.TrimSpace(typeAndRule[0]), strings.TrimSpace(typeAndRule[1]), typeAndRule[2:], nil
}

func parseSubRule(tp, payload string, params []string) (C.Rule, error) {
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
