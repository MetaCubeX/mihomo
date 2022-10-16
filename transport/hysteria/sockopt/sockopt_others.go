//go:build !linux

package sockopt

import (
	"errors"
	"net"
	"syscall"
)

func bindRawConn(network string, c syscall.RawConn, bindIface *net.Interface) error {
	return errors.New("binding interface is not supported on the current system")
}
