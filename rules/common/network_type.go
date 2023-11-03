package common

import (
	"fmt"
	C "github.com/metacubex/mihomo/constant"
	"strings"
)

type NetworkType struct {
	*Base
	network C.NetWork
	adapter string
}

func NewNetworkType(network, adapter string) (*NetworkType, error) {
	ntType := NetworkType{
		Base: &Base{},
	}

	ntType.adapter = adapter
	switch strings.ToUpper(network) {
	case "TCP":
		ntType.network = C.TCP
	case "UDP":
		ntType.network = C.UDP
	default:
		return nil, fmt.Errorf("unsupported network type, only TCP/UDP")
	}

	return &ntType, nil
}

func (n *NetworkType) RuleType() C.RuleType {
	return C.Network
}

func (n *NetworkType) Match(metadata *C.Metadata) (bool, string) {
	return n.network == metadata.NetWork, n.adapter
}

func (n *NetworkType) Adapter() string {
	return n.adapter
}

func (n *NetworkType) Payload() string {
	return n.network.String()
}
