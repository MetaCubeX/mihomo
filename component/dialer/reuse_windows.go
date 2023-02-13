package dialer

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

func addrReuseToListenConfig(lc *net.ListenConfig) {
	addControlToListenConfig(lc, func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
		})
	})
}
