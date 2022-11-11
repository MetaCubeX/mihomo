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
