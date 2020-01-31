package socks

import (
	"net"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/socks5"
)

type fakeConn struct {
	net.PacketConn
	rAddr   net.Addr
	payload []byte
	bufRef  []byte
}

func (c *fakeConn) Data() []byte {
	return c.payload
}

// WriteBack wirtes UDP packet with source(ip, port) = `addr`
func (c *fakeConn) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	return c.PacketConn.WriteTo(packet, c.rAddr)
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *fakeConn) LocalAddr() net.Addr {
	return c.PacketConn.LocalAddr()
}

func (c *fakeConn) Close() error {
	pool.BufPool.Put(c.bufRef[:cap(c.bufRef)])
	return nil
}
