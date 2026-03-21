//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package sockopt

import (
	"golang.org/x/sys/unix"
)

func reuseControl(fd uintptr) error {
	e1 := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	e2 := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)

	if e1 != nil {
		return e1
	}

	if e2 != nil {
		return e2
	}

	return nil
}
