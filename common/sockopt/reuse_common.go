package sockopt

import (
	"net"
	"syscall"
)

func RawConnReuseaddr(rc syscall.RawConn) (err error) {
	var innerErr error
	err = rc.Control(func(fd uintptr) {
		innerErr = reuseControl(fd)
	})

	if innerErr != nil {
		err = innerErr
	}
	return
}

func UDPReuseaddr(c net.PacketConn) error {
	if c, ok := c.(syscall.Conn); ok {
		rc, err := c.SyscallConn()
		if err != nil {
			return err
		}

		return RawConnReuseaddr(rc)
	}
	return nil
}
