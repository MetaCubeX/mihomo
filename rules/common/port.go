package common

import (
	"fmt"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type Port struct {
	*Base
	adapter    string
	port       string
	ruleType   C.RuleType
	portRanges utils.IntRanges[uint16]
}

func (p *Port) RuleType() C.RuleType {
	return p.ruleType
}

func (p *Port) Match(metadata *C.Metadata) (bool, string) {
	targetPort := metadata.DstPort
	switch p.ruleType {
	case C.InPort:
		targetPort = metadata.InPort
	case C.SrcPort:
		targetPort = metadata.SrcPort
	}
	return p.portRanges.Check(targetPort), p.adapter
}

func (p *Port) Adapter() string {
	return p.adapter
}

func (p *Port) Payload() string {
	return p.port
}

func NewPort(port string, adapter string, ruleType C.RuleType) (*Port, error) {
	portRanges, err := utils.NewIntRanges[uint16](port)
	if err != nil {
		return nil, fmt.Errorf("%w, %w", errPayload, err)
	}

	if len(portRanges) == 0 {
		return nil, errPayload
	}

	return &Port{
		Base:       &Base{},
		adapter:    adapter,
		port:       port,
		ruleType:   ruleType,
		portRanges: portRanges,
	}, nil
}

var _ C.Rule = (*Port)(nil)
