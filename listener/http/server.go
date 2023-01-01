package http

import (
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/cache"
	C "github.com/Dreamacro/clash/constant"
)

type Listener struct {
	listener net.Listener
	addr     string
	closed   bool
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *Listener) Address() string {
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed = true
	return l.listener.Close()
}

func New(addr string, in chan<- C.ConnContext, additions ...inbound.Addition) (*Listener, error) {
	return NewWithAuthenticate(addr, in, true, additions...)
}

func NewWithAuthenticate(addr string, in chan<- C.ConnContext, authenticate bool, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-HTTP"),
			inbound.WithSpecialRules(""),
		}
	}
	l, err := inbound.Listen("tcp", addr)

	if err != nil {
		return nil, err
	}

	var c *cache.LruCache[string, bool]
	if authenticate {
		c = cache.New[string, bool](cache.WithAge[string, bool](30))
	}

	hl := &Listener{
		listener: l,
		addr:     addr,
	}
	go func() {
		for {
			conn, err := hl.listener.Accept()
			if err != nil {
				if hl.closed {
					break
				}
				continue
			}
			go HandleConn(conn, in, c, additions...)
		}
	}()

	return hl, nil
}
