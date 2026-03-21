package constant

import "net"

type Listener interface {
	RawAddress() string
	Address() string
	Close() error
}

type MultiAddrListener interface {
	Close() error
	Config() string
	AddrList() (addrList []net.Addr)
}

type InboundListener interface {
	Name() string
	Listen(tunnel Tunnel) error
	Close() error
	Address() string
	RawAddress() string
	Config() InboundConfig
}

type InboundConfig interface {
	Name() string
	Equal(config InboundConfig) bool
}
