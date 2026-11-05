//go:build !linux

package ebpf

import (
	C "github.com/metacubex/mihomo/constant"
	"net/netip"
)

type InboundConfig struct {
	Enable                bool
	LANInterfaces         []string
	TProxyPort            uint16
	AutoDirectOffload     bool
	BypassSrcPorts        []uint16
	BypassDstPorts        []uint16
	ProxySrcPorts         []uint16
	ProxyDstPorts         []uint16
	BypassSrcIPs          []netip.Prefix
	BypassDstIPs          []netip.Prefix
	ProxySrcIPs           []netip.Prefix
	ProxyDstIPs           []netip.Prefix
	DirectIPRuleProviders []string
}

type Manager struct{}

func StartManager(InboundConfig, C.Tunnel) (*Manager, error) { return nil, ErrUnsupported }
func (*Manager) Close() error                                { return nil }
