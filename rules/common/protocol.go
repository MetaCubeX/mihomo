package common

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

type Protocol struct {
	Base
	protocol string
	adapter  string
}

func NewProtocol(protocol string, adapter string) (*Protocol, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	switch protocol {
	case C.ProtocolBitTorrent:
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return &Protocol{
		Base:     Base{},
		protocol: protocol,
		adapter:  adapter,
	}, nil
}

func (p *Protocol) RuleType() C.RuleType {
	return C.Protocol
}

func (p *Protocol) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	return metadata.SniffProtocol == p.protocol, p.adapter
}

func (p *Protocol) Adapter() string {
	return p.adapter
}

func (p *Protocol) Payload() string {
	return p.protocol
}

var _ C.Rule = (*Protocol)(nil)
