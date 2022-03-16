//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package dialer

import (
	"net"
)

func addrReuseToListenConfig(*net.ListenConfig) {}
