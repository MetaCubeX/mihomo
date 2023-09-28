package constant

type Tunnel interface {
	// HandleTCPConn will handle a tcp connection blocking
	HandleTCPConn(connCtx ConnContext)
	// HandleUDPPacket will handle a udp packet nonblocking
	HandleUDPPacket(packet PacketAdapter)
	// NatTable return nat table
	NatTable() NatTable
}
