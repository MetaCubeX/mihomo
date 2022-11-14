//go:build linux

package dialer

import (
	"net"
	"net/netip"
	"syscall"
)

func bindMarkToDialer(mark int, dialer *net.Dialer, _ string, _ netip.Addr) {
	dialer.Control = bindMarkToControl(mark, dialer.Control)
}

func bindMarkToListenConfig(mark int, lc *net.ListenConfig, _, _ string) {
	lc.Control = bindMarkToControl(mark, lc.Control)
}

func bindMarkToControl(mark int, chain controlFn) controlFn {
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
			innerErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		})
		if innerErr != nil {
			err = innerErr
		}
		return
	}
}
