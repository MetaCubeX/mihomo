package net

import (
	"net"
	"runtime"
	"time"
)

type refConn struct {
	conn net.Conn
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

func NewRefConn(conn net.Conn, ref any) net.Conn {
	return &refConn{conn: conn, ref: ref}
}

type refPacketConn struct {
	pc  net.PacketConn
	ref any
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

func NewRefPacketConn(pc net.PacketConn, ref any) net.PacketConn {
	return &refPacketConn{pc: pc, ref: ref}
}
