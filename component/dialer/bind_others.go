//go:build !linux && !darwin && !windows

package dialer

import (
	"net"
	"net/netip"
)

func bindIfaceToDialer(ifaceName string, dialer *net.Dialer, network string, destination netip.Addr) error {
	return fallbackBindIfaceToDialer(ifaceName, dialer, network, destination)
}

func bindIfaceToListenConfig(ifaceName string, lc *net.ListenConfig, network, address string, rAddrPort netip.AddrPort) (string, error) {
	return fallbackBindIfaceToListenConfig(ifaceName, lc, network, address, rAddrPort)
}

func ParseNetwork(network string, addr netip.Addr) string {
	return fallbackParseNetwork(network, addr)
}
