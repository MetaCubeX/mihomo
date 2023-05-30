package common

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/common/utils"
	C "github.com/Dreamacro/clash/constant"
)

type Port struct {
	*Base
	adapter  string
	port     string
	ruleType C.RuleType
	portList []utils.Range[uint16]
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

	for _, pr := range p.portList {
		if pr.Contains(uint16(port)) {
			return true
		}
	}

	return false
}

func NewPort(port string, adapter string, ruleType C.RuleType) (*Port, error) {
	ports := strings.Split(port, "/")
	if len(ports) > 28 {
		return nil, fmt.Errorf("%s, too many ports to use, maximum support 28 ports", errPayload.Error())
	}

	var portRange, err = utils.NewIntRangeList(ports, errPayload)

	if err != nil {
		return nil, err
	}

	if len(portRange) == 0 {
		return nil, errPayload
	}

	return &Port{
		Base:     &Base{},
		adapter:  adapter,
		port:     port,
		ruleType: ruleType,
		portList: portRange,
	}, nil
}

var _ C.Rule = (*Port)(nil)
