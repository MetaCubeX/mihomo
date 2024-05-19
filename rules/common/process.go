package common

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"

	"github.com/dlclark/regexp2"
)

type Process struct {
	*Base
	adapter  string
	process  string
	nameOnly bool
	regexp   *regexp2.Regexp
}

func (ps *Process) RuleType() C.RuleType {
	if ps.nameOnly {
		if ps.regexp != nil {
			return C.ProcessNameRegex
		}
		return C.ProcessName
	}

	if ps.regexp != nil {
		return C.ProcessPathRegex
	}
	return C.ProcessPath
}

func (ps *Process) Match(metadata *C.Metadata) (bool, string) {
	if ps.nameOnly {
		if ps.regexp != nil {
			match, _ := ps.regexp.MatchString(metadata.Process)
			return match, ps.adapter
		}
		return strings.EqualFold(metadata.Process, ps.process), ps.adapter
	}

	if ps.regexp != nil {
		match, _ := ps.regexp.MatchString(metadata.ProcessPath)
		return match, ps.adapter
	}
	return strings.EqualFold(metadata.ProcessPath, ps.process), ps.adapter
}

func (ps *Process) Adapter() string {
	return ps.adapter
}

func (ps *Process) Payload() string {
	return ps.process
}

func (ps *Process) ShouldFindProcess() bool {
	return true
}

func NewProcess(process string, adapter string, nameOnly bool, regex bool) (*Process, error) {
	var r *regexp2.Regexp
	var err error
	if regex {
		r, err = regexp2.Compile(process, regexp2.IgnoreCase)
		if err != nil {
			return nil, err
		}
	}
	return &Process{
		Base:     &Base{},
		adapter:  adapter,
		process:  process,
		nameOnly: nameOnly,
		regexp:   r,
	}, nil
}
