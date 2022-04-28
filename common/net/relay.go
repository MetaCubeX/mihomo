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

	go func() {
		buf := pool.Get(pool.RelayBufferSize)
		// Wrapping to avoid using *net.TCPConn.(ReadFrom)
		// See also https://github.com/Dreamacro/clash/pull/1209
		_, err := io.CopyBuffer(WriteOnlyWriter{Writer: leftConn}, ReadOnlyReader{Reader: rightConn}, buf)
		pool.Put(buf)
		leftConn.SetReadDeadline(time.Now())
		ch <- err
	}()

	buf := pool.Get(pool.RelayBufferSize)
	io.CopyBuffer(WriteOnlyWriter{Writer: rightConn}, ReadOnlyReader{Reader: leftConn}, buf)
	pool.Put(buf)
	rightConn.SetReadDeadline(time.Now())
	<-ch
}
