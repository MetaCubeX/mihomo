package http

import (
	"context"
	"github.com/database64128/tfo-go"
	"net"
	"time"

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

func New(addr string, inboundTfo bool, in chan<- C.ConnContext) (*Listener, error) {
	return NewWithAuthenticate(addr, in, true, inboundTfo)
}

func NewWithAuthenticate(addr string, in chan<- C.ConnContext, authenticate bool, inboundTfo bool) (*Listener, error) {
	lc := tfo.ListenConfig{
		DisableTFO: !inboundTfo,
	}
	l, err := lc.Listen(context.Background(), "tcp", addr)

	if err != nil {
		return nil, err
	}

	var c *cache.Cache[string, bool]
	if authenticate {
		c = cache.New[string, bool](time.Second * 30)
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
