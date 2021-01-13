package dialer

import (
	"net"
	"syscall"
)

type controlFn = func(network, address string, c syscall.RawConn) error

func bindControl(ifaceIdx int) controlFn {
	return func(network, address string, c syscall.RawConn) error {
		ipStr, _, err := net.SplitHostPort(address)
		if err == nil {
			ip := net.ParseIP(ipStr)
			if ip != nil && !ip.IsGlobalUnicast() {
				return nil
			}
		}

		return c.Control(func(fd uintptr) {
			switch network {
			case "tcp4", "udp4":
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, ifaceIdx)
			case "tcp6", "udp6":
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, ifaceIdx)
			}
		})
	}
}

func bindIfaceToDialer(dialer *net.Dialer, ifaceName string) error {
	iface, err, _ := ifaceSingle.Do(func() (interface{}, error) {
		return net.InterfaceByName(ifaceName)
	})
	if err != nil {
		return err
	}

	dialer.Control = bindControl(iface.(*net.Interface).Index)
	return nil
}

func bindIfaceToListenConfig(lc *net.ListenConfig, ifaceName string) error {
	iface, err, _ := ifaceSingle.Do(func() (interface{}, error) {
		return net.InterfaceByName(ifaceName)
	})
	if err != nil {
		return err
	}

	lc.Control = bindControl(iface.(*net.Interface).Index)
	return nil
}
