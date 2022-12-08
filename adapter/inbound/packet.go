package inbound

import (
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
	"net"
	"strconv"
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
	for _, addition := range additions {
		addition.Apply(metadata)
	}
	if ip, port, err := parseAddr(packet.LocalAddr()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
	}

	if port, err := strconv.Atoi(metadata.DstPort); err == nil {
		metadata.RawSrcAddr = packet.LocalAddr()
		metadata.RawDstAddr = &net.UDPAddr{IP: metadata.DstIP.AsSlice(), Port: port}
	}

	return &PacketAdapter{
		packet,
		metadata,
	}
}
