package constant

import (
	"io"
	"net"
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
	Generator(addr *Addr) (ProxyAdapter, error)
}
