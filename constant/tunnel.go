package constant

import "net"

type Tunnel interface {
	// HandleTCPConn will handle a tcp connection blocking
	HandleTCPConn(conn net.Conn, metadata *Metadata)
	// HandleTCPConnWithError will handle a tcp connection blocking, and return a more accurate error.
	HandleTCPConnWithError(conn net.Conn, metadata *Metadata) error
	// HandleUDPPacket will handle a udp packet nonblocking
	HandleUDPPacket(packet UDPPacket, metadata *Metadata)
	// NatTable return nat table
	NatTable() NatTable
}
