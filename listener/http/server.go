package http

import (
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/cache"
	C "github.com/Dreamacro/clash/constant"
)

type Listener struct {
	listener     net.Listener
	addr         string
	closed       bool
	name         string
	specialRules string
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
	return NewWithAuthenticate(addr, "DEFAULT-HTTP", "", in, true)
}

func NewWithInfos(addr, name, specialRules string, in chan<- C.ConnContext) (*Listener, error) {
	return NewWithAuthenticate(addr, name, specialRules, in, true)
}

func NewWithAuthenticate(addr, name, specialRules string, in chan<- C.ConnContext, authenticate bool) (*Listener, error) {
	l, err := inbound.Listen("tcp", addr)

	if err != nil {
		return nil, err
	}

	var c *cache.LruCache[string, bool]
	if authenticate {
		c = cache.New[string, bool](cache.WithAge[string, bool](30))
	}

	hl := &Listener{
		listener:     l,
		name:         name,
		specialRules: specialRules,
		addr:         addr,
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
			go HandleConn(hl.name, hl.specialRules, conn, in, c)
		}
	}()

	return hl, nil
}
