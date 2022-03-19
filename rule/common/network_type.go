package common

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	"strings"
)

type NetworkType struct {
	*Base
	network C.NetWork
	adapter string
}

func NewNetworkType(network, adapter string) (*NetworkType, error) {
	var netType C.NetWork
	switch strings.ToUpper(network) {
	case "TCP":
		netType = C.TCP
		break
	case "UDP":
		netType = C.UDP
		break
	default:
		return nil, fmt.Errorf("unsupported network type, only TCP/UDP")
	}
	return &NetworkType{
		Base:    &Base{},
		network: netType,
		adapter: adapter,
	}, nil
}

func (n *NetworkType) RuleType() C.RuleType {
	return C.Network
}

func (n *NetworkType) Match(metadata *C.Metadata) bool {
	return n.network == metadata.NetWork
}

func (n *NetworkType) Adapter() string {
	return n.adapter
}

func (n *NetworkType) Payload() string {
	return n.network.String()
}
