package inbound

import (
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

// PacketAdapter is a UDP Packet adapter for socks/redir/tun
type PacketAdapter struct {
	C.UDPPacket
	metadata *C.Metadata
}

// Metadata returns destination metadata
func (s *PacketAdapter) Metadata() *C.Metadata {
	return s.metadata
}

// NewPacket is PacketAdapter generator
func NewPacket(target socks5.Addr, packet C.UDPPacket, source C.Type, additions ...Addition) C.PacketAdapter {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.UDP
	metadata.Type = source
	additions = append(additions, WithSrcAddr(packet.LocalAddr()))
	if p, ok := packet.(C.UDPPacketInAddr); ok {
		additions = append(additions, WithInAddr(p.InAddr()))
	}
	for _, addition := range additions {
		addition.Apply(metadata)
	}

	return &PacketAdapter{
		packet,
		metadata,
	}
}
