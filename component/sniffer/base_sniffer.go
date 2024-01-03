package sniffer

import (
	"errors"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"
)

type SnifferConfig struct {
	OverrideDest bool
	Ports        utils.IntRanges[uint16]
}

type BaseSniffer struct {
	ports              utils.IntRanges[uint16]
	supportNetworkType constant.NetWork
}

// Protocol implements sniffer.Sniffer
func (*BaseSniffer) Protocol() string {
	return "unknown"
}

// SniffData implements sniffer.Sniffer
func (*BaseSniffer) SniffData(bytes []byte) (string, error) {
	return "", errors.New("TODO")
}

// SupportNetwork implements sniffer.Sniffer
func (bs *BaseSniffer) SupportNetwork() constant.NetWork {
	return bs.supportNetworkType
}

// SupportPort implements sniffer.Sniffer
func (bs *BaseSniffer) SupportPort(port uint16) bool {
	return bs.ports.Check(port)
}

func NewBaseSniffer(ports utils.IntRanges[uint16], networkType constant.NetWork) *BaseSniffer {
	return &BaseSniffer{
		ports:              ports,
		supportNetworkType: networkType,
	}
}

var _ sniffer.Sniffer = (*BaseSniffer)(nil)
