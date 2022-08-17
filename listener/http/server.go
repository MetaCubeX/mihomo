package http

import (
	"net"

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

func New(addr string, in chan<- C.ConnContext) (*Listener, error) {
	return NewWithAuthenticate(addr, in, true)
}

func NewWithAuthenticate(addr string, in chan<- C.ConnContext, authenticate bool) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	var c *cache.LruCache
	if authenticate {
		c = cache.New(cache.WithAge(30))
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
			go HandleConn(conn, in, c)
		}
	}()

	return hl, nil
}
