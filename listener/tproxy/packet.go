package tproxy

import (
	"net"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type packet struct {
	lAddr *net.UDPAddr
	buf   *buf.Buffer
}

func (c *packet) Data() *buf.Buffer {
	return c.buf
}

// WriteBack opens a new socket binding `addr` to write UDP packet back
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	tc, err := dialUDP("udp", addr.(*net.UDPAddr), c.lAddr)
	if err != nil {
		n = 0
		return
	}
	n, err = tc.Write(b)
	tc.Close()
	return
}

func (c *packet) WritePacket(buffer *buf.Buffer, addr M.Socksaddr) error {
	defer buffer.Release()
	tc, err := dialUDP("udp", addr.UDPAddr(), c.lAddr)
	defer tc.Close()
	if err != nil {
		return err
	}
	_, err = tc.Write(buffer.Bytes())
	return nil
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.lAddr
}
