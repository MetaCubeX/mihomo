//go:build !go1.23

package keepalive

import (
	"net"
	"time"
)

type TCPConn interface {
	net.Conn
	SetKeepAlive(keepalive bool) error
	SetKeepAlivePeriod(d time.Duration) error
}

func tcpKeepAlive(tcp TCPConn) {
	if DisableKeepAlive() {
		_ = tcp.SetKeepAlive(false)
	} else {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(KeepAliveInterval())
	}
}

func setNetDialer(dialer *net.Dialer) {
	if DisableKeepAlive() {
		dialer.KeepAlive = -1 // If negative, keep-alive probes are disabled.
	} else {
		dialer.KeepAlive = KeepAliveInterval()
	}
}

func setNetListenConfig(lc *net.ListenConfig) {
	if DisableKeepAlive() {
		lc.KeepAlive = -1 // If negative, keep-alive probes are disabled.
	} else {
		lc.KeepAlive = KeepAliveInterval()
	}
}
