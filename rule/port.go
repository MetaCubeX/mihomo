package rules

import (
	"fmt"
	"strconv"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type portReal struct {
	portStart int
	portEnd   int
}

type Port struct {
	*Base
	adapter  string
	port     string
	isSource bool
	portList []portReal
}

func (p *Port) RuleType() C.RuleType {
	if p.isSource {
		return C.SrcPort
	}
	return C.DstPort
}

func (p *Port) Match(metadata *C.Metadata) bool {
	if p.isSource {
		return p.matchPortReal(metadata.SrcPort)
	}
	return p.matchPortReal(metadata.DstPort)
}

func (p *Port) Adapter() string {
	return p.adapter
}

func (p *Port) Payload() string {
	return p.port
}

func (p *Port) ShouldResolveIP() bool {
	return false
}

func (p *Port) matchPortReal(portRef string) bool {
	port, _ := strconv.Atoi(portRef)
	var rs bool
	for _, pr := range p.portList {
		if pr.portEnd == -1 {
			rs = port == pr.portStart
		} else {
			rs = port >= pr.portStart && port <= pr.portEnd
		}
		if rs {
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

	var portList []portReal
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
			portList = append(portList, portReal{int(portStart), -1})
		case 2:
			portEnd, err := strconv.ParseUint(strings.Trim(subPorts[1], "[ ]"), 10, 16)
			if err != nil {
				return nil, errPayload
			}

			shouldReverse := portStart > portEnd
			if shouldReverse {
				portList = append(portList, portReal{int(portEnd), int(portStart)})
			} else {
				portList = append(portList, portReal{int(portStart), int(portEnd)})
			}
		}
	}

	if len(portList) == 0 {
		return nil, errPayload
	}

	return &Port{
		Base:     &Base{},
		adapter:  adapter,
		port:     port,
		isSource: isSource,
		portList: portList,
	}, nil
}

var _ C.Rule = (*Port)(nil)
