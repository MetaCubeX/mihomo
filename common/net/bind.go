package net

import "net"

type bindPacketConn struct {
	EnhancePacketConn
	rAddr net.Addr
}

func (c *bindPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.EnhancePacketConn.ReadFrom(b)
	return n, err
}

func (c *bindPacketConn) WaitRead() (data []byte, put func(), err error) {
	data, put, _, err = c.EnhancePacketConn.WaitReadFrom()
	return
}

func (c *bindPacketConn) Write(b []byte) (n int, err error) {
	return c.EnhancePacketConn.WriteTo(b, c.rAddr)
}

func (c *bindPacketConn) RemoteAddr() net.Addr {
	return c.rAddr
}

func (c *bindPacketConn) LocalAddr() net.Addr {
	if c.EnhancePacketConn.LocalAddr() == nil {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	} else {
		return c.EnhancePacketConn.LocalAddr()
	}
}

func (c *bindPacketConn) Upstream() any {
	return c.EnhancePacketConn
}

func NewBindPacketConn(pc net.PacketConn, rAddr net.Addr) net.Conn {
	return &bindPacketConn{
		EnhancePacketConn: NewEnhancePacketConn(pc),
		rAddr:             rAddr,
	}
}
