package net

import (
	"net"
	"runtime"
	"time"

	"github.com/Dreamacro/clash/common/buf"
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

type refPacketConn struct {
	pc  EnhancePacketConn
	ref any
}

func (pc *refPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	defer runtime.KeepAlive(pc.ref)
	return pc.pc.WaitReadFrom()
}

func (pc *refPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	defer runtime.KeepAlive(pc.ref)
	return pc.pc.ReadFrom(p)
}

func (pc *refPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	defer runtime.KeepAlive(pc.ref)
	return pc.pc.WriteTo(p, addr)
}

func (pc *refPacketConn) Close() error {
	defer runtime.KeepAlive(pc.ref)
	return pc.pc.Close()
}

func (pc *refPacketConn) LocalAddr() net.Addr {
	defer runtime.KeepAlive(pc.ref)
	return pc.pc.LocalAddr()
}

func (pc *refPacketConn) SetDeadline(t time.Time) error {
	defer runtime.KeepAlive(pc.ref)
	return pc.pc.SetDeadline(t)
}

func (pc *refPacketConn) SetReadDeadline(t time.Time) error {
	defer runtime.KeepAlive(pc.ref)
	return pc.pc.SetReadDeadline(t)
}

func (pc *refPacketConn) SetWriteDeadline(t time.Time) error {
	defer runtime.KeepAlive(pc.ref)
	return pc.pc.SetWriteDeadline(t)
}

func (pc *refPacketConn) Upstream() any {
	return pc.pc
}

func (pc *refPacketConn) ReaderReplaceable() bool { // Relay() will handle reference
	return true
}

func (pc *refPacketConn) WriterReplaceable() bool { // Relay() will handle reference
	return true
}

func NewRefPacketConn(pc net.PacketConn, ref any) net.PacketConn {
	return &refPacketConn{pc: NewEnhancePacketConn(pc), ref: ref}
}
