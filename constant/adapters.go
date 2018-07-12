package constant

import (
	"io"
	"net"
)

// Adapter Type
const (
	Direct AdapterType = iota
	Reject
	Selector
	Shadowsocks
	URLTest
)

type ProxyAdapter interface {
	ReadWriter() io.ReadWriter
	Conn() net.Conn
	Close()
}

type ServerAdapter interface {
	Addr() *Addr
	Connect(ProxyAdapter)
	Close()
}

type Proxy interface {
	Name() string
	Type() AdapterType
	Generator(addr *Addr) (ProxyAdapter, error)
}

// AdapterType is enum of adapter type
type AdapterType int

func (at AdapterType) String() string {
	switch at {
	case Direct:
		return "Direct"
	case Reject:
		return "Reject"
	case Selector:
		return "Selector"
	case Shadowsocks:
		return "Shadowsocks"
	case URLTest:
		return "URLTest"
	default:
		return "Unknow"
	}
}
