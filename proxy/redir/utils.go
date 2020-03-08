package redir

import (
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

type fakeConn struct {
	net.PacketConn
	origDst net.Addr
	rAddr   net.Addr
	buf     []byte
}

func (c *fakeConn) Data() []byte {
	return c.buf
}

// WriteBack opens a new socket binding `origDst` to wirte UDP packet back
func (c *fakeConn) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	tc, err := dialUDP("udp", c.origDst.(*net.UDPAddr), c.rAddr.(*net.UDPAddr))
	if err != nil {
		n = 0
		return
	}
	n, err = tc.Write(b)
	tc.Close()
	return
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *fakeConn) LocalAddr() net.Addr {
	return c.rAddr
}

func (c *fakeConn) Close() error {
	err := c.PacketConn.Close()
	pool.BufPool.Put(c.buf[:cap(c.buf)])
	return err
}
