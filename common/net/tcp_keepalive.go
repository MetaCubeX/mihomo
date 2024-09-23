package net

import (
	"net"
	"runtime"
	"time"
)

var (
	KeepAliveIdle     = 0 * time.Second
	KeepAliveInterval = 0 * time.Second
	DisableKeepAlive  = false
)

func TCPKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		if runtime.GOOS == "android" || DisableKeepAlive {
			_ = tcp.SetKeepAlive(false)
		} else {
			tcpKeepAlive(tcp)
		}
	}
}
