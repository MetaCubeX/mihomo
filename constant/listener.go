package constant

import "net"

type Listener interface {
	RawAddress() string
	Address() string
	Close() error
}

type AdvanceListener interface {
	Close()
	Config() string
	HandleConn(conn net.Conn, in chan<- ConnContext)
}

type NewListener interface {
	Name() string
	Listen(tcpIn chan<- ConnContext, udpIn chan<- PacketAdapter) error
	Close() error
	Address() string
	RawAddress() string
}
