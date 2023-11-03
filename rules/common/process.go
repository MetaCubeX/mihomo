package common

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

type Process struct {
	*Base
	adapter  string
	process  string
	nameOnly bool
}

func (ps *Process) RuleType() C.RuleType {
	if ps.nameOnly {
		return C.Process
	}

	return C.ProcessPath
}

func (ps *Process) Match(metadata *C.Metadata) (bool, string) {
	if ps.nameOnly {
		return strings.EqualFold(metadata.Process, ps.process), ps.adapter
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

func NewProcess(process string, adapter string, nameOnly bool) (*Process, error) {
	return &Process{
		Base:     &Base{},
		adapter:  adapter,
		process:  process,
		nameOnly: nameOnly,
	}, nil
}
