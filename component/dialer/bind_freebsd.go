package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// directFib is the alternate routing table (FIB) that sing-tun populates with
// the original physical routes while TUN auto-route takes over the default FIB.
// Binding DIRECT sockets to this FIB makes their traffic egress the physical
// interface instead of looping back through the tun device.
//
// FreeBSD has neither Linux's SO_BINDTODEVICE nor macOS's IP_BOUND_IF; SO_SETFIB
// is the platform's mechanism for steering a socket onto an alternate routing
// table, so it is what we use to prevent the DIRECT-outbound loopback.
const directFib = 1

func bindControl(fib int) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		addrPort, err := netip.ParseAddrPort(address)
		if err == nil && !addrPort.Addr().IsGlobalUnicast() {
			return
		}

		var innerErr error
		err = c.Control(func(fd uintptr) {
			innerErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SETFIB, fib)
		})

		if innerErr != nil {
			err = innerErr
		}

		return
	}
}

func bindIfaceToDialer(ifaceName string, dialer *net.Dialer, _ string, _ netip.Addr) error {
	addControlToDialer(dialer, bindControl(directFib))
	return nil
}

func bindIfaceToListenConfig(ifaceName string, lc *net.ListenConfig, _, address string, rAddrPort netip.AddrPort) (string, error) {
	addControlToListenConfig(lc, bindControl(directFib))
	return address, nil
}

func ParseNetwork(network string, addr netip.Addr) string {
	return network
}
