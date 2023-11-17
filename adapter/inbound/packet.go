package inbound

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

// NewPacket is PacketAdapter generator
func NewPacket(target socks5.Addr, packet C.UDPPacket, source C.Type, additions ...Addition) (C.UDPPacket, *C.Metadata) {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.UDP
	metadata.Type = source
	metadata.RawSrcAddr = packet.LocalAddr()
	metadata.RawDstAddr = metadata.UDPAddr()
	ApplyAdditions(metadata, WithSrcAddr(packet.LocalAddr()))
	if p, ok := packet.(C.UDPPacketInAddr); ok {
		ApplyAdditions(metadata, WithInAddr(p.InAddr()))
	}
	ApplyAdditions(metadata, additions...)

	return packet, metadata
}
