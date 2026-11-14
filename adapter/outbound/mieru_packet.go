package outbound

import (
	"errors"
	"net"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/transport/socks5"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
)

// The SDK's UDPAssociateWrapper rejects domain replies, but mita's default
// PacketOverStream mode returns the original SOCKS header for known peers.
type mieruPacketConn struct {
	*mierucommon.PacketOverStreamTunnel
}

func (c *mieruPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	data, put, addr, err := c.WaitReadFrom()
	if err != nil {
		return 0, addr, err
	}
	defer put()
	return copy(p, data), addr, nil
}

func (c *mieruPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	// Read a complete SDK frame: a short buffer leaves its payload unread and
	// would desynchronize the stream. The frame length is an unsigned uint16.
	buffer := pool.Get(65535)
	defer func() {
		if err != nil {
			_ = pool.Put(buffer)
		}
	}()
	n, _, err := c.PacketOverStreamTunnel.ReadFrom(buffer)
	if err != nil {
		return nil, nil, nil, err
	}
	address, data, err := socks5.DecodeUDPPacket(buffer[:n])
	if err != nil {
		return nil, nil, nil, err
	}
	addr = address.NetAddr()
	if addr == nil {
		return nil, nil, nil, errors.New("invalid Mieru UDP reply address")
	}
	return data, func() { _ = pool.Put(buffer) }, addr, nil
}

func (c *mieruPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), p)
	if err != nil {
		return 0, err
	}
	if _, err = c.PacketOverStreamTunnel.WriteTo(packet, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}
