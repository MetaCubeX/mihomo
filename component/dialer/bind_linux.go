package dialer

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

type controlFn = func(network, address string, c syscall.RawConn) error

func bindControl(ifaceName string, chain controlFn) controlFn {
	return func(network, address string, c syscall.RawConn) (err error) {
		defer func() {
			if err == nil && chain != nil {
				err = chain(network, address, c)
			}
		}()

		addrPort, err := netip.ParseAddrPort(address)
		if err == nil && !addrPort.Addr().IsGlobalUnicast() {
			return
		}

		var innerErr error
		err = c.Control(func(fd uintptr) {
			innerErr = unix.BindToDevice(int(fd), ifaceName)
		})

		if innerErr != nil {
			err = innerErr
		}

		return
	}
}

func bindIfaceToDialer(ifaceName string, dialer *net.Dialer, _ string, _ netip.Addr) error {
	dialer.Control = bindControl(ifaceName, dialer.Control)

	return nil
}

func bindIfaceToListenConfig(ifaceName string, lc *net.ListenConfig, _, address string) (string, error) {
	lc.Control = bindControl(ifaceName, lc.Control)

	return address, nil
}
