package dialer

import (
	"net"
	"syscall"
)

type controlFn = func(network, address string, c syscall.RawConn) error

func bindControl(ifaceName string) controlFn {
	return func(network, address string, c syscall.RawConn) error {
		ipStr, _, err := net.SplitHostPort(address)
		if err == nil {
			ip := net.ParseIP(ipStr)
			if ip != nil && !ip.IsGlobalUnicast() {
				return nil
			}
		}

		return c.Control(func(fd uintptr) {
			syscall.BindToDevice(int(fd), ifaceName)
		})
	}
}

func bindIfaceToDialer(dialer *net.Dialer, ifaceName string) error {
	dialer.Control = bindControl(ifaceName)

	return nil
}

func bindIfaceToListenConfig(lc *net.ListenConfig, ifaceName string) error {
	lc.Control = bindControl(ifaceName)

	return nil
}
