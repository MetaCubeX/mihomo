//go:build !linux

package nat

import "net"

func addition(*net.TCPConn) {}
