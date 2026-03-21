package packet

import (
	"net"
	"runtime"
	"time"
)

type refPacketConn struct {
	pc  EnhancePacketConn
	ref any
}

func (c *refPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	defer runtime.KeepAlive(c.ref)
	return c.pc.WaitReadFrom()
}

func (c *refPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	defer runtime.KeepAlive(c.ref)
	return c.pc.ReadFrom(p)
}

func (c *refPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	defer runtime.KeepAlive(c.ref)
	return c.pc.WriteTo(p, addr)
}

func (c *refPacketConn) Close() error {
	defer runtime.KeepAlive(c.ref)
	return c.pc.Close()
}

func (c *refPacketConn) LocalAddr() net.Addr {
	defer runtime.KeepAlive(c.ref)
	return c.pc.LocalAddr()
}

func (c *refPacketConn) SetDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.ref)
	return c.pc.SetDeadline(t)
}

func (c *refPacketConn) SetReadDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.ref)
	return c.pc.SetReadDeadline(t)
}

func (c *refPacketConn) SetWriteDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.ref)
	return c.pc.SetWriteDeadline(t)
}

func (c *refPacketConn) Upstream() any {
	return c.pc
}

func (c *refPacketConn) ReaderReplaceable() bool { // Relay() will handle reference
	return true
}

func (c *refPacketConn) WriterReplaceable() bool { // Relay() will handle reference
	return true
}

func NewRefPacketConn(pc net.PacketConn, ref any) EnhancePacketConn {
	rPC := &refPacketConn{pc: NewEnhancePacketConn(pc), ref: ref}
	if singPC, isSingPC := pc.(SingPacketConn); isSingPC {
		return &refSingPacketConn{
			refPacketConn:  rPC,
			singPacketConn: singPC,
		}
	}
	return rPC
}
