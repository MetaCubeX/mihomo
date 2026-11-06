package miu

import (
	"net"
	"syscall"
)

// setCork corks or uncorks conn (TCP_CORK): small writes made while corked do not leave in a packet of
// their own, everything goes out when the cork is removed.
func setCork(conn net.Conn, on bool) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	v := 0
	if on {
		v = 1
	}
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CORK, v)
	})
}
