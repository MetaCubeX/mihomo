//go:build go1.23

package keepalive

import "net"

func keepAliveConfig() net.KeepAliveConfig {
	config := net.KeepAliveConfig{
		Enable:   true,
		Idle:     KeepAliveIdle(),
		Interval: KeepAliveInterval(),
	}
	if !SupportTCPKeepAliveCount() {
		// it's recommended to set both Idle and Interval to non-negative values in conjunction with a -1
		// for Count on those old Windows if you intend to customize the TCP keep-alive settings.
		config.Count = -1
	}
	return config
}

func tcpKeepAlive(tcp *net.TCPConn) {
	if DisableKeepAlive() {
		_ = tcp.SetKeepAlive(false)
	} else {
		_ = tcp.SetKeepAliveConfig(keepAliveConfig())
	}
}

func setNetDialer(dialer *net.Dialer) {
	if DisableKeepAlive() {
		dialer.KeepAlive = -1 // If negative, keep-alive probes are disabled.
		dialer.KeepAliveConfig.Enable = false
	} else {
		dialer.KeepAliveConfig = keepAliveConfig()
	}
}

func setNetListenConfig(lc *net.ListenConfig) {
	if DisableKeepAlive() {
		lc.KeepAlive = -1 // If negative, keep-alive probes are disabled.
		lc.KeepAliveConfig.Enable = false
	} else {
		lc.KeepAliveConfig = keepAliveConfig()
	}
}
