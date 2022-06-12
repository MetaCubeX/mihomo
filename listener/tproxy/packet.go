package tproxy

import (
	"net"
	"net/netip"

	"github.com/Dreamacro/clash/common/pool"
)

type packet struct {
	lAddr netip.AddrPort
	buf   []byte
}

func (c *packet) Data() []byte {
	return c.buf
}

// WriteBack opens a new socket binding `addr` to write UDP packet back
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	tc, err := dialUDP("udp", addr.(*net.UDPAddr).AddrPort(), c.lAddr)
	if err != nil {
		n = 0
		return
	}
	n, err = tc.Write(b)
	tc.Close()
	return
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.lAddr.Addr().AsSlice(), Port: int(c.lAddr.Port()), Zone: c.lAddr.Addr().Zone()}
}

func (c *packet) Drop() {
	pool.Put(c.buf)
}
