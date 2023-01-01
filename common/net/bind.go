package net

import "net"

type bindPacketConn struct {
	net.PacketConn
	rAddr net.Addr
}

func (wpc *bindPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = wpc.PacketConn.ReadFrom(b)
	return n, err
}

func (wpc *bindPacketConn) Write(b []byte) (n int, err error) {
	return wpc.PacketConn.WriteTo(b, wpc.rAddr)
}

func (wpc *bindPacketConn) RemoteAddr() net.Addr {
	return wpc.rAddr
}

func (wpc *bindPacketConn) LocalAddr() net.Addr {
	if wpc.PacketConn.LocalAddr() == nil {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	} else {
		return wpc.PacketConn.LocalAddr()
	}
}

func NewBindPacketConn(pc net.PacketConn, rAddr net.Addr) net.Conn {
	return &bindPacketConn{
		PacketConn: pc,
		rAddr:      rAddr,
	}
}
