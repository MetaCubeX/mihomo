package logic

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/rules/common"
)

type SubRule struct {
	*common.Base
	payload           string
	payloadRule       C.Rule
	subName           string
	subRules          *map[string][]C.Rule
	shouldFindProcess *bool
	shouldResolveIP   *bool
}

func NewSubRule(payload, subName string, sub *map[string][]C.Rule,
	parse func(tp, payload, target string, params []string, subRules *map[string][]C.Rule) (parsed C.Rule, parseErr error)) (*SubRule, error) {
	payloadRule, err := ParseRuleByPayload(fmt.Sprintf("(%s)", payload), parse)
	if err != nil {
		return nil, err
	}
	if len(payloadRule) != 1 {
		return nil, fmt.Errorf("Sub-Rule rule must contain one rule")
	}

	return &SubRule{
		Base:        &common.Base{},
		payload:     payload,
		payloadRule: payloadRule[0],
		subName:     subName,
		subRules:    sub,
	}, nil
}

func (r *SubRule) RuleType() C.RuleType {
	return C.SubRules
}

func (r *SubRule) Match(metadata *C.Metadata) (bool, string) {

	return match(metadata, r.subName, r.subRules)
}

func match(metadata *C.Metadata, name string, subRules *map[string][]C.Rule) (bool, string) {
	for _, rule := range (*subRules)[name] {
		if m, a := rule.Match(metadata); m {
			if rule.RuleType() == C.SubRules {
				match(metadata, rule.Adapter(), subRules)
			} else {
				return m, a
			}
		}
	}
	return false, ""
}

func (r *SubRule) ShouldResolveIP() bool {
	if r.shouldResolveIP == nil {
		s := false
		for _, rule := range (*r.subRules)[r.subName] {
			s = s || rule.ShouldResolveIP()
		}
		r.shouldResolveIP = &s
	}

	return *r.shouldResolveIP
}

func (r *SubRule) ShouldFindProcess() bool {
	if r.shouldFindProcess == nil {
		s := false
		for _, rule := range (*r.subRules)[r.subName] {
			s = s || rule.ShouldFindProcess()
		}
		r.shouldFindProcess = &s
	}

	return *r.shouldFindProcess
}

func (r *SubRule) Adapter() string {
	return r.subName
}

func (r *SubRule) Payload() string {
	return r.payload
}
