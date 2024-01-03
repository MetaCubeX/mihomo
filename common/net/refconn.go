package net

import (
	"net"
	"runtime"
	"time"

	"github.com/metacubex/mihomo/common/buf"
)

type refConn struct {
	conn ExtendedConn
	ref  any
}

func (c *refConn) Read(b []byte) (n int, err error) {
	defer runtime.KeepAlive(c.ref)
	return c.conn.Read(b)
}

func (c *refConn) Write(b []byte) (n int, err error) {
	defer runtime.KeepAlive(c.ref)
	return c.conn.Write(b)
}

func (c *refConn) Close() error {
	defer runtime.KeepAlive(c.ref)
	return c.conn.Close()
}

func (c *refConn) LocalAddr() net.Addr {
	defer runtime.KeepAlive(c.ref)
	return c.conn.LocalAddr()
}

func (c *refConn) RemoteAddr() net.Addr {
	defer runtime.KeepAlive(c.ref)
	return c.conn.RemoteAddr()
}

func (c *refConn) SetDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.ref)
	return c.conn.SetDeadline(t)
}

func (c *refConn) SetReadDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.ref)
	return c.conn.SetReadDeadline(t)
}

func (c *refConn) SetWriteDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.ref)
	return c.conn.SetWriteDeadline(t)
}

func (c *refConn) Upstream() any {
	return c.conn
}

func (c *refConn) ReadBuffer(buffer *buf.Buffer) error {
	defer runtime.KeepAlive(c.ref)
	return c.conn.ReadBuffer(buffer)
}

func (c *refConn) WriteBuffer(buffer *buf.Buffer) error {
	defer runtime.KeepAlive(c.ref)
	return c.conn.WriteBuffer(buffer)
}

func (c *refConn) ReaderReplaceable() bool { // Relay() will handle reference
	return true
}

func (c *refConn) WriterReplaceable() bool { // Relay() will handle reference
	return true
}

var _ ExtendedConn = (*refConn)(nil)

func NewRefConn(conn net.Conn, ref any) net.Conn {
	return &refConn{conn: NewExtendedConn(conn), ref: ref}
}
