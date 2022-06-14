package net

import (
	"io"
	"net"
	"time"
)

// Relay copies between left and right bidirectionally.
func Relay(leftConn, rightConn net.Conn) {
	ch := make(chan error)

	tcpKeepAlive(leftConn)
	tcpKeepAlive(rightConn)

	go func() {
		// Wrapping to avoid using *net.TCPConn.(ReadFrom)
		// See also https://github.com/Dreamacro/clash/pull/1209
		_, err := io.Copy(WriteOnlyWriter{Writer: leftConn}, ReadOnlyReader{Reader: rightConn})
		_ = leftConn.SetReadDeadline(time.Now())
		ch <- err
	}()

	_, _ = io.Copy(WriteOnlyWriter{Writer: rightConn}, ReadOnlyReader{Reader: leftConn})
	_ = rightConn.SetReadDeadline(time.Now())
	<-ch
}

func tcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
	}
}
