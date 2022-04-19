package common

import (
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type Process struct {
	*Base
	adapter  string
	process  string
	nameOnly bool
}

func (ps *Process) RuleType() C.RuleType {
	return C.Process
}

func (ps *Process) Match(metadata *C.Metadata) bool {
	if ps.nameOnly {
		return strings.EqualFold(metadata.Process, ps.process)
	}
	return strings.EqualFold(metadata.ProcessPath, ps.process)
}

func (ps *Process) Adapter() string {
	return ps.adapter
}

func (ps *Process) Payload() string {
	return ps.process
}

func NewProcess(process string, adapter string, nameOnly bool) (*Process, error) {
	return &Process{
		Base:     &Base{},
		adapter:  adapter,
		process:  process,
		nameOnly: nameOnly,
	}, nil
}
