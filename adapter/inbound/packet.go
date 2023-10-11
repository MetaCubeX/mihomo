package inbound

import (
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

// NewPacket is PacketAdapter generator
func NewPacket(target socks5.Addr, packet C.UDPPacket, source C.Type, additions ...Addition) (C.UDPPacket, *C.Metadata) {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.UDP
	metadata.Type = source
	ApplyAdditions(metadata, WithSrcAddr(packet.LocalAddr()))
	if p, ok := packet.(C.UDPPacketInAddr); ok {
		ApplyAdditions(metadata, WithInAddr(p.InAddr()))
	}
	ApplyAdditions(metadata, additions...)

	return packet, metadata
}
