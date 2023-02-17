package tunnel

import (
	"net"

	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
)

type packet struct {
	pc      net.PacketConn
	rAddr   net.Addr
	payload []byte
}

func (c *packet) Data() []byte {
	return c.payload
}

// WriteBack write UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	return c.pc.WriteTo(b, c.rAddr)
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}

func (c *packet) Drop() {
	pool.Put(c.payload)
}

func (c *packet) InAddr() net.Addr {
	return c.pc.LocalAddr()
}

func (c *packet) SetNatTable(natTable C.NatTable) {
	// no need
}

func (c *packet) SetUdpInChan(in chan<- C.PacketAdapter) {
	// no need
}
