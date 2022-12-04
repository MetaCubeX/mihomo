package tproxy

import (
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
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

func (l *Listener) handleTProxy(name, specialRules string, conn net.Conn, in chan<- C.ConnContext) {
	target := socks5.ParseAddrToSocksAddr(conn.LocalAddr())
	conn.(*net.TCPConn).SetKeepAlive(true)
	in <- inbound.NewSocketWithInfos(target, conn, C.TPROXY, name, specialRules)
}

func New(addr string, in chan<- C.ConnContext) (*Listener, error) {
	return NewWithInfos(addr, "DEFAULT-TPROXY", "", in)
}

func NewWithInfos(addr, name, specialRules string, in chan<- C.ConnContext) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	tl := l.(*net.TCPListener)
	rc, err := tl.SyscallConn()
	if err != nil {
		return nil, err
	}

	err = setsockopt(rc, addr)
	if err != nil {
		return nil, err
	}

	rl := &Listener{
		listener:     l,
		addr:         addr,
		name:         name,
		specialRules: specialRules,
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if rl.closed {
					break
				}
				continue
			}
			go rl.handleTProxy(rl.name, rl.specialRules, c, in)
		}
	}()

	return rl, nil
}
