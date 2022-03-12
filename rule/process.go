package rules

import (
	"path/filepath"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type Process struct {
	adapter  string
	process  string
	nameOnly bool
}

func (ps *Process) RuleType() C.RuleType {
	return C.Process
}

func (ps *Process) Match(metadata *C.Metadata) bool {
	if ps.nameOnly {
		return strings.EqualFold(filepath.Base(metadata.ProcessPath), ps.process)
	}

	return strings.EqualFold(metadata.ProcessPath, ps.process)
}

func (ps *Process) Adapter() string {
	return ps.adapter
}

func (ps *Process) Payload() string {
	return ps.process
}

func (ps *Process) ShouldResolveIP() bool {
	return false
}

func (ps *Process) ShouldFindProcess() bool {
	return true
}

func NewProcess(process string, adapter string, nameOnly bool) (*Process, error) {
	return &Process{
		adapter:  adapter,
		process:  process,
		nameOnly: nameOnly,
	}, nil
}
