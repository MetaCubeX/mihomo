package common

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

type SniffProtocolRule struct {
	Base
	protocol string
	adapter  string
}

func (s *SniffProtocolRule) RuleType() C.RuleType {
	return C.SniffProtocol
}

func (s *SniffProtocolRule) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	return strings.EqualFold(metadata.SniffProtocol, s.protocol), s.adapter
}

func (s *SniffProtocolRule) Adapter() string {
	return s.adapter
}

func (s *SniffProtocolRule) Payload() string {
	return s.protocol
}

func NewSniffProtocol(protocol, adapter string) (*SniffProtocolRule, error) {
	return &SniffProtocolRule{
		Base:     Base{},
		protocol: strings.ToLower(protocol),
		adapter:  adapter,
	}, nil
}

var _ C.Rule = (*SniffProtocolRule)(nil)
