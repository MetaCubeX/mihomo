package sockopt

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func bindRawConn(network string, c syscall.RawConn, bindIface *net.Interface) error {
	var err1, err2 error
	err1 = c.Control(func(fd uintptr) {
		if bindIface != nil {
			err2 = unix.BindToDevice(int(fd), bindIface.Name)
		}
	})
	if err1 != nil {
		return err1
	} else {
		return err2
	}
}
