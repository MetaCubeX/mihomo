//go:build !linux

package ebpf

import (
	C "github.com/metacubex/mihomo/constant"
)

type InboundConfig struct {
	Enable            bool
	LANInterfaces     []string
	TProxyPort        uint16
	AutoDirectOffload bool
	BypassSrcPorts    []uint16
	BypassDstPorts    []uint16
}

type Manager struct{}

func StartManager(InboundConfig, C.Tunnel) (*Manager, error) { return nil, ErrUnsupported }
func (*Manager) Close() error                                { return nil }
