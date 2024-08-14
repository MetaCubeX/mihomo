//go:build go1.23

package net

import "net"

func tcpKeepAlive(tcp *net.TCPConn) {
	config := net.KeepAliveConfig{
		Enable:   true,
		Idle:     KeepAliveIdle,
		Interval: KeepAliveInterval,
	}
	if !SupportTCPKeepAliveCount() {
		// it's recommended to set both Idle and Interval to non-negative values in conjunction with a -1
		// for Count on those old Windows if you intend to customize the TCP keep-alive settings.
		config.Count = -1
	}
	_ = tcp.SetKeepAliveConfig(config)
}
