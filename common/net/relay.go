package net

import (
	"io"
	"net"
	"time"

	"github.com/Dreamacro/clash/common/pool"
)

// Relay copies between left and right bidirectionally.
func Relay(leftConn, rightConn net.Conn) {
	ch := make(chan error)

	tcpKeepAlive(leftConn)
	tcpKeepAlive(rightConn)

	go func() {
		buf := pool.Get(pool.RelayBufferSize)
		// Wrapping to avoid using *net.TCPConn.(ReadFrom)
		// See also https://github.com/Dreamacro/clash/pull/1209
		_, err := io.CopyBuffer(WriteOnlyWriter{Writer: leftConn}, ReadOnlyReader{Reader: rightConn}, buf)
		_ = pool.Put(buf)
		_ = leftConn.SetReadDeadline(time.Now())
		ch <- err
	}()

	buf := pool.Get(pool.RelayBufferSize)
	_, _ = io.CopyBuffer(WriteOnlyWriter{Writer: rightConn}, ReadOnlyReader{Reader: leftConn}, buf)
	_ = pool.Put(buf)
	_ = rightConn.SetReadDeadline(time.Now())
	<-ch
}

func tcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
	}
}
