package dialer

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/component/iface"
)

func LookupLocalAddrFromIfaceName(ifaceName string, network string, destination netip.Addr, port int) (net.Addr, error) {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return nil, err
	}

	var addr netip.Prefix
	switch network {
	case "udp4", "tcp4":
		addr, err = ifaceObj.PickIPv4Addr(destination)
	case "tcp6", "udp6":
		addr, err = ifaceObj.PickIPv6Addr(destination)
	default:
		if destination.IsValid() {
			if destination.Is4() || destination.Is4In6() {
				addr, err = ifaceObj.PickIPv4Addr(destination)
			} else {
				addr, err = ifaceObj.PickIPv6Addr(destination)
			}
		} else {
			addr, err = ifaceObj.PickIPv4Addr(destination)
		}
	}
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(network, "tcp") {
		return &net.TCPAddr{
			IP:   addr.Addr().AsSlice(),
			Port: port,
		}, nil
	} else if strings.HasPrefix(network, "udp") {
		return &net.UDPAddr{
			IP:   addr.Addr().AsSlice(),
			Port: port,
		}, nil
	}

	return nil, iface.ErrAddrNotFound
}

func fallbackBindIfaceToDialer(ifaceName string, dialer *net.Dialer, network string, destination netip.Addr) error {
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

func fallbackBindIfaceToListenConfig(ifaceName string, _ *net.ListenConfig, network, address string) (string, error) {
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

func fallbackParseNetwork(network string, addr netip.Addr) string {
	// fix fallbackBindIfaceToListenConfig() force bind to an ipv4 address
	if !strings.HasSuffix(network, "4") &&
		!strings.HasSuffix(network, "6") &&
		addr.Unmap().Is6() {
		network += "6"
	}
	return network
}
