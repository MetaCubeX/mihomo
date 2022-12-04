package constant

import "net"

type Listener interface {
	RawAddress() string
	Address() string
	Close() error
}

type AdvanceListener interface {
	Close() error
	Config() string
	AddrList() (addrList []net.Addr)
	HandleConn(conn net.Conn, in chan<- ConnContext)
}

type InboundListener interface {
	Name() string
	Listen(tcpIn chan<- ConnContext, udpIn chan<- PacketAdapter) error
	Close() error
	Address() string
	RawAddress() string
	Config() InboundConfig
}

type InboundConfig interface {
	Name() string
	Equal(config InboundConfig) bool
}
