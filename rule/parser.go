package rules

import (
	C "github.com/Dreamacro/clash/constant"
	RC "github.com/Dreamacro/clash/rule/common"
	"github.com/Dreamacro/clash/rule/logic"
	RP "github.com/Dreamacro/clash/rule/provider"
	"github.com/Dreamacro/clash/rule/ruleparser"
)

func ParseRule(tp, payload, target string, params []string) (parsed C.Rule, parseErr error) {
	parsed, parseErr = ruleparser.ParseSameRule(tp, payload, target, params)
	if ruleparser.IsUnsupported(parseErr) {
		switch tp {
		case "AND":
			parsed, parseErr = logic.NewAND(payload, target)
		case "OR":
			parsed, parseErr = logic.NewOR(payload, target)
		case "NOT":
			parsed, parseErr = logic.NewNOT(payload, target)
		case "RULE-SET":
			noResolve := RC.HasNoResolve(params)
			parsed, parseErr = RP.NewRuleSet(payload, target, noResolve)
		case "MATCH":
			parsed = RC.NewMatch(target)
			parseErr = nil
		default:
			parseErr = ruleparser.NewUnsupportedError(tp)
		}
	}

	if parseErr != nil {
		return nil, parseErr
	}

	ruleExtra := &C.RuleExtra{
		Network:      RC.FindNetwork(params),
		SourceIPs:    RC.FindSourceIPs(params),
		ProcessNames: RC.FindProcessName(params),
	}

	parsed.SetRuleExtra(ruleExtra)

	return
}
