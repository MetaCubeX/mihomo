//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package dialer

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func addrReuseToListenConfig(lc *net.ListenConfig) {
	addControlToListenConfig(lc, func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		})
	})
}
