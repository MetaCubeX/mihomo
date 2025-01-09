package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

func bindControl(ifaceName string) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
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
	addControlToDialer(dialer, bindControl(ifaceName))

	return nil
}

func bindIfaceToListenConfig(ifaceName string, lc *net.ListenConfig, _, address string, rAddrPort netip.AddrPort) (string, error) {
	addControlToListenConfig(lc, bindControl(ifaceName))

	return address, nil
}

func ParseNetwork(network string, addr netip.Addr) string {
	return network
}
