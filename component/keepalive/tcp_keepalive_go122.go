//go:build !go1.23

package keepalive

import "net"

func tcpKeepAlive(tcp *net.TCPConn) {
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
