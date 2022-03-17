package adapter

// Handler is a TCP/UDP connection handler that implements
// HandleTCPConn and HandleUDPConn methods.
type Handler interface {
	HandleTCPConn(TCPConn)
	HandleUDPConn(UDPConn)
}
