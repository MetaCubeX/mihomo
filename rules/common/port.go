package common

import (
	"fmt"
	"strconv"

	"github.com/Dreamacro/clash/common/utils"
	C "github.com/Dreamacro/clash/constant"
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
	return p.matchPortReal(targetPort), p.adapter
}

func (p *Port) Adapter() string {
	return p.adapter
}

func (p *Port) Payload() string {
	return p.port
}

func (p *Port) matchPortReal(portRef string) bool {
	port, _ := strconv.Atoi(portRef)

	return p.portRanges.Check(uint16(port))
}

func NewPort(port string, adapter string, ruleType C.RuleType) (*Port, error) {
	portRanges, err := utils.NewIntRanges[uint16](port)
	if err != nil {
		return nil, fmt.Errorf("%w, %s", errPayload, err.Error())
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
