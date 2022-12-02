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
	isSource bool
	portList []utils.Range[uint16]
}

func (p *Port) RuleType() C.RuleType {
	if p.isSource {
		return C.SrcPort
	}
	return C.DstPort
}

func (p *Port) Match(metadata *C.Metadata) (bool, string) {
	if p.isSource {
		return p.matchPortReal(metadata.SrcPort), p.adapter
	}
	return p.matchPortReal(metadata.DstPort), p.adapter
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

func NewPort(port string, adapter string, isSource bool) (*Port, error) {
	ports := strings.Split(port, "/")
	if len(ports) > 28 {
		return nil, fmt.Errorf("%s, too many ports to use, maximum support 28 ports", errPayload.Error())
	}

	var portRange []utils.Range[uint16]
	for _, p := range ports {
		if p == "" {
			continue
		}

		subPorts := strings.Split(p, "-")
		subPortsLen := len(subPorts)
		if subPortsLen > 2 {
			return nil, errPayload
		}

		portStart, err := strconv.ParseUint(strings.Trim(subPorts[0], "[ ]"), 10, 16)
		if err != nil {
			return nil, errPayload
		}

		switch subPortsLen {
		case 1:
			portRange = append(portRange, *utils.NewRange(uint16(portStart), uint16(portStart)))
		case 2:
			portEnd, err := strconv.ParseUint(strings.Trim(subPorts[1], "[ ]"), 10, 16)
			if err != nil {
				return nil, errPayload
			}

			portRange = append(portRange, *utils.NewRange(uint16(portStart), uint16(portEnd)))
		}
	}

	if len(portRange) == 0 {
		return nil, errPayload
	}

	return &Port{
		Base:     &Base{},
		adapter:  adapter,
		port:     port,
		isSource: isSource,
		portList: portRange,
	}, nil
}

var _ C.Rule = (*Port)(nil)
