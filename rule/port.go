package rules

import (
	"strconv"

	C "github.com/Dreamacro/clash/constant"
)

type Port struct {
	adapter  string
	port     string
	isSource bool
	network  C.NetWork
}

func (p *Port) RuleType() C.RuleType {
	if p.isSource {
		return C.SrcPort
	}
	return C.DstPort
}

func (p *Port) Match(metadata *C.Metadata) bool {
	if p.isSource {
		return metadata.SrcPort == p.port
	}
	return metadata.DstPort == p.port
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

func (p *Port) NetWork() C.NetWork {
	return p.network
}

func NewPort(port string, adapter string, isSource bool, network C.NetWork) (*Port, error) {
	_, err := strconv.Atoi(port)
	if err != nil {
		return nil, errPayload
	}
	return &Port{
		adapter:  adapter,
		port:     port,
		isSource: isSource,
		network:  network,
	}, nil
}
