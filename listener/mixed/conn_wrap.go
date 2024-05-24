package mixed

import (
	"io"
	"net"
	"time"
)

type MyConn struct {
	net.Conn
	buf        []byte
	bufLen     int
	localAddr  net.Addr
	remoteAddr net.Addr
	peeked     bool
}

func NewMyConn(conn net.Conn) *MyConn {
	MyConn := MyConn{
		Conn:       conn,
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}
	return &MyConn
}

func (c *MyConn) Peek(num int) ([]byte, error) {
	c.peeked = true
	c.bufLen = num
	c.buf = make([]byte, c.bufLen)
	_, err := io.ReadFull(c.Conn, c.buf)
	return c.buf, err
}

func (c *MyConn) Read(b []byte) (n int, err error) {
	if c.peeked {
		n := copy(b, c.buf)
		if n < c.bufLen {
			c.bufLen -= n
			c.buf = c.buf[n:]
		} else {
			c.peeked = false
			c.buf = nil
			c.bufLen = 0
		}
		return n, nil
	} else {
		if c.Conn == nil {
			return 0, io.EOF
		}
		return c.Conn.Read(b)
	}
}

func (c *MyConn) Write(b []byte) (n int, err error) {
	if c.Conn != nil {
		return c.Conn.Write(b)
	}
	return 0, io.EOF
}

func (c *MyConn) Close() error {
	c.buf = nil
	conn := c.Conn
	c.Conn = nil
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *MyConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *MyConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *MyConn) SetDeadline(t time.Time) error {
	if c.Conn != nil {
		c.Conn.SetDeadline(t)
		return nil
	} else {
		return io.EOF
	}
}

func (c *MyConn) SetReadDeadline(t time.Time) error {
	if c.Conn != nil {
		c.Conn.SetReadDeadline(t)
		return nil
	} else {
		return io.EOF
	}
}
