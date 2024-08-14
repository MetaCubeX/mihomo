//go:build !go1.23

package net

import "net"

func TCPKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(KeepAliveInterval)
	}
}
