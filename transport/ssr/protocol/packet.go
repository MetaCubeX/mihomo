package protocol

import (
	"net"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
)

type PacketConn struct {
	N.EnhancePacketConn
	Protocol
}

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	err := c.EncodePacket(buf, b)
	if err != nil {
		return 0, err
	}
	_, err = c.EnhancePacketConn.WriteTo(buf.Bytes(), addr)
	return len(b), err
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.EnhancePacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	decoded, err := c.DecodePacket(b[:n])
	if err != nil {
		return n, addr, err
	}
	copy(b, decoded)
	return len(decoded), addr, nil
}

func (c *PacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	data, put, addr, err = c.EnhancePacketConn.WaitReadFrom()
	if err != nil {
		return
	}
	data, err = c.DecodePacket(data)
	if err != nil {
		if put != nil {
			put()
		}
		data = nil
		put = nil
		return
	}
	return
}
