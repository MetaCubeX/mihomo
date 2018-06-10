package constant

import (
	"io"
)

type ProxyAdapter interface {
	Writer() io.Writer
	Reader() io.Reader
	Close()
}

type ServerAdapter interface {
	Addr() *Addr
	ProxyAdapter
}

type Proxy interface {
	Generator(addr *Addr) (ProxyAdapter, error)
}
