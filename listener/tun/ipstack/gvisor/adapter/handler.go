//go:build !no_gvisor

package adapter

// Handler is a TCP/UDP connection handler that implements
// HandleTCPConn and HandleUDPConn methods.
type Handler interface {
	HandleTCP(TCPConn)
	HandleUDP(UDPConn)
}

// TCPHandleFunc handles incoming TCP connection.
type TCPHandleFunc func(TCPConn)

// UDPHandleFunc handles incoming UDP connection.
type UDPHandleFunc func(UDPConn)
