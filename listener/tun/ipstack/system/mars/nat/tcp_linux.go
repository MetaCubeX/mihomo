package nat

import (
	"net"
	"syscall"
)

func addition(c *net.TCPConn) {
	sys, err := c.SyscallConn()
	if err == nil {
		_ = sys.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_NO_CHECK, 1)
		})
	}
}
