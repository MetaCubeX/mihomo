package dialer

import (
	"net"
	"syscall"
)

func bindIfaceToDialer(dialer *net.Dialer, ifaceName string) error {
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.BindToDevice(int(fd), ifaceName)
		})
	}

	return nil
}

func bindIfaceToListenConfig(lc *net.ListenConfig, ifaceName string) error {
	lc.Control = func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.BindToDevice(int(fd), ifaceName)
		})
	}

	return nil
}
