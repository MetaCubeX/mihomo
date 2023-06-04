//go:build !linux && !darwin && !windows

package dialer

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func bindIfaceToDialer(ifaceName string, dialer *net.Dialer, network string, destination netip.Addr) error {
	if !destination.IsGlobalUnicast() {
		return nil
	}

	local := uint64(0)
	if dialer.LocalAddr != nil {
		_, port, err := net.SplitHostPort(dialer.LocalAddr.String())
		if err == nil {
			local, _ = strconv.ParseUint(port, 10, 16)
		}
	}

	addr, err := LookupLocalAddrFromIfaceName(ifaceName, network, destination, int(local))
	if err != nil {
		return err
	}

	dialer.LocalAddr = addr

	return nil
}

func bindIfaceToListenConfig(ifaceName string, _ *net.ListenConfig, network, address string) (string, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		port = "0"
	}

	local, _ := strconv.ParseUint(port, 10, 16)

	addr, err := LookupLocalAddrFromIfaceName(ifaceName, network, netip.Addr{}, int(local))
	if err != nil {
		return "", err
	}

	return addr.String(), nil
}

func ParseNetwork(network string, addr netip.Addr) string {
	// fix bindIfaceToListenConfig() force bind to an ipv4 address
	if !strings.HasSuffix(network, "4") &&
		!strings.HasSuffix(network, "6") &&
		addr.Unmap().Is6() {
		network += "6"
	}
	return network
}
