package socks

import (
	"net"

	"github.com/Dreamacro/clash/transport/socks5"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type packet struct {
	pc      net.PacketConn
	rAddr   net.Addr
	payload *buf.Buffer
}

func (c *packet) Data() *buf.Buffer {
	return c.payload
}

// WriteBack write UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	return c.pc.WriteTo(packet, c.rAddr)
}

func (c *packet) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	header := buf.With(buffer.ExtendHeader(3 + M.SocksaddrSerializer.AddrPortLen(destination)))
	common.Must(header.WriteZeroN(3))
	common.Must(M.SocksaddrSerializer.WriteAddrPort(header, destination))
	return common.Error(c.pc.WriteTo(buffer.Bytes(), c.rAddr))
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}
