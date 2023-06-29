package dialer

import (
	"net"
	"net/netip"
	"strings"

	"github.com/Dreamacro/clash/component/iface"
)

func LookupLocalAddrFromIfaceName(ifaceName string, network string, destination netip.Addr, port int) (net.Addr, error) {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return nil, err
	}

	var addr *netip.Prefix
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
