package sniffer

import (
	"errors"

	"github.com/Dreamacro/clash/common/utils"
	"github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/sniffer"
)

type SnifferConfig struct {
	OverrideDest bool
	Ports        []utils.Range[uint16]
}

type BaseSniffer struct {
	ports              []utils.Range[uint16]
	supportNetworkType constant.NetWork
}

// Protocol implements sniffer.Sniffer
func (*BaseSniffer) Protocol() string {
	return "unknown"
}

// SniffTCP implements sniffer.Sniffer
func (*BaseSniffer) SniffTCP(bytes []byte) (string, error) {
	return "", errors.New("TODO")
}

// SupportNetwork implements sniffer.Sniffer
func (bs *BaseSniffer) SupportNetwork() constant.NetWork {
	return bs.supportNetworkType
}

// SupportPort implements sniffer.Sniffer
func (bs *BaseSniffer) SupportPort(port uint16) bool {
	for _, portRange := range bs.ports {
		if portRange.Contains(port) {
			return true
		}
	}
	return false
}

func NewBaseSniffer(ports []utils.Range[uint16], networkType constant.NetWork) *BaseSniffer {
	return &BaseSniffer{
		ports:              ports,
		supportNetworkType: networkType,
	}
}

var _ sniffer.Sniffer = (*BaseSniffer)(nil)
