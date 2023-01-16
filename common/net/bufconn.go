package net

import (
	"bufio"
	"net"

	"github.com/Dreamacro/clash/common/buf"
)

var _ ExtendedConn = (*BufferedConn)(nil)

type BufferedConn struct {
	r *bufio.Reader
	ExtendedConn
}

func NewBufferedConn(c net.Conn) *BufferedConn {
	if bc, ok := c.(*BufferedConn); ok {
		return bc
	}
	return &BufferedConn{bufio.NewReader(c), NewExtendedConn(c)}
}

// Reader returns the internal bufio.Reader.
func (c *BufferedConn) Reader() *bufio.Reader {
	return c.r
}

// Peek returns the next n bytes without advancing the reader.
func (c *BufferedConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *BufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *BufferedConn) ReadByte() (byte, error) {
	return c.r.ReadByte()
}

func (c *BufferedConn) UnreadByte() error {
	return c.r.UnreadByte()
}

func (c *BufferedConn) Buffered() int {
	return c.r.Buffered()
}

func (c *BufferedConn) ReadBuffer(buffer *buf.Buffer) (err error) {
	if c.r.Buffered() > 0 {
		_, err = buffer.ReadOnceFrom(c.r)
		return
	}
	return c.ExtendedConn.ReadBuffer(buffer)
}

func (c *BufferedConn) Upstream() any {
	return c.ExtendedConn
}

func (c *BufferedConn) ReaderReplaceable() bool {
	if c.r.Buffered() > 0 {
		return false
	}
	return true
}
