package common

import (
	"strings"

	"github.com/metacubex/mihomo/component/wildcard"
	C "github.com/metacubex/mihomo/constant"

	"github.com/dlclark/regexp2"
)

type Process struct {
	Base
	pattern  string
	adapter  string
	ruleType C.RuleType
	regexp   *regexp2.Regexp
}

func (ps *Process) Payload() string {
	return ps.pattern
}

func (ps *Process) Adapter() string {
	return ps.adapter
}

func (ps *Process) RuleType() C.RuleType {
	return ps.ruleType
}

func (ps *Process) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if helper.FindProcess != nil {
		helper.FindProcess()
	}
	var target string
	switch ps.ruleType {
	case C.ProcessName, C.ProcessNameRegex, C.ProcessNameWildcard:
		target = metadata.Process
	default:
		target = metadata.ProcessPath
	}

	switch ps.ruleType {
	case C.ProcessNameRegex, C.ProcessPathRegex:
		match, _ := ps.regexp.MatchString(target)
		return match, ps.adapter
	case C.ProcessNameWildcard, C.ProcessPathWildcard:
		return wildcard.Match(strings.ToLower(ps.pattern), strings.ToLower(target)), ps.adapter
	default:
		return strings.EqualFold(target, ps.pattern), ps.adapter
	}
}

func NewProcess(pattern string, adapter string, ruleType C.RuleType) (*Process, error) {
	ps := &Process{
		Base:     Base{},
		pattern:  pattern,
		adapter:  adapter,
		ruleType: ruleType,
	}
	switch ps.ruleType {
	case C.ProcessNameRegex, C.ProcessPathRegex:
		r, err := regexp2.Compile(pattern, regexp2.IgnoreCase)
		if err != nil {
			return nil, err
		}
		ps.regexp = r
	default:
	}
	return ps, nil
}

var _ C.Rule = (*Process)(nil)
