package constant

import (
	"context"
	"net"
	"net/netip"
)

// ICMPRouter optionally resolves TUN echo requests through the normal rule engine.
type ICMPRouter interface {
	ResolveICMP(metadata *Metadata) (Proxy, error)
}

// ICMPEchoProxy performs a real ICMP echo probe, not a discovery/DERP ping.
// It does not transport arbitrary ICMP messages or preserve probe payload sizes.
type ICMPEchoProxy interface {
	SupportICMP() bool
	PingICMP(context.Context, netip.Addr) error
}

type Tunnel interface {
	// HandleTCPConn will handle a tcp connection blocking
	HandleTCPConn(conn net.Conn, metadata *Metadata)
	// HandleUDPPacket will handle a udp packet nonblocking
	HandleUDPPacket(packet UDPPacket, metadata *Metadata)
	// NatTable return nat table
	NatTable() NatTable
}
