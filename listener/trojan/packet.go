package trojan

import (
	"errors"
	"net"
)

type packet struct {
	pc      net.PacketConn
	rAddr   net.Addr
	payload []byte
	put     func()
}

func (c *packet) Data() []byte {
	return c.payload
}

// WriteBack wirtes UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	if addr == nil {
		err = errors.New("address is invalid")
		return
	}
	return c.pc.WriteTo(b, addr)
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}

func (c *packet) Drop() {
	if c.put != nil {
		c.put()
		c.put = nil
	}
	c.payload = nil
}

func (c *packet) InAddr() net.Addr {
	return c.pc.LocalAddr()
}
