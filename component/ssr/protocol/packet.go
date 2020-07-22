package protocol

import (
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

// NewPacketConn returns a net.NewPacketConn with protocol decoding/encoding
func NewPacketConn(pc net.PacketConn, p Protocol) net.PacketConn {
	return &PacketConn{PacketConn: pc, Protocol: p.initForConn(nil)}
}

// PacketConn represents a protocol packet connection
type PacketConn struct {
	net.PacketConn
	Protocol
}

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	buf, err := c.EncodePacket(b)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(buf, addr)
	return len(b), err
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	bb, length, err := c.DecodePacket(b[:n])
	if err != nil {
		return n, addr, err
	}
	copy(b, bb)
	return length, addr, err
}
