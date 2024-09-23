//go:build !go1.23

package net

import "net"

func tcpKeepAlive(tcp *net.TCPConn) {
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(KeepAliveInterval)
}
