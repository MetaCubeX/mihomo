package inbound

import (
	C "github.com/Dreamacro/clash/constant"
	M "github.com/sagernet/sing/common/metadata"
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
func NewPacket(target M.Socksaddr, packet C.UDPPacket, source C.Type) *PacketAdapter {
	metadata := socksAddrToMetadata(target)
	metadata.NetWork = C.UDP
	metadata.Type = source
	if ip, port, err := parseAddr(packet.LocalAddr().String()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
	}

	return &PacketAdapter{
		UDPPacket: packet,
		metadata:  metadata,
	}
}
