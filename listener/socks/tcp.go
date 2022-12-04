package socks

import (
	"io"
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	authStore "github.com/Dreamacro/clash/listener/auth"
	"github.com/Dreamacro/clash/transport/socks4"
	"github.com/Dreamacro/clash/transport/socks5"
)

type Listener struct {
	listener     net.Listener
	addr         string
	closed       bool
	specialRules string
	name         string
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
	return NewWithInfos(addr, "DEFAULT-SOCKS", "", in)
}

func NewWithInfos(addr, name, specialRules string, in chan<- C.ConnContext) (*Listener, error) {
	l, err := inbound.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	sl := &Listener{
		listener:     l,
		addr:         addr,
		name:         name,
		specialRules: specialRules,
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			go handleSocks(sl.name, sl.specialRules, c, in)
		}
	}()

	return sl, nil
}

func handleSocks(name, specialRules string, conn net.Conn, in chan<- C.ConnContext) {
	conn.(*net.TCPConn).SetKeepAlive(true)
	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	switch head[0] {
	case socks4.Version:
		HandleSocks4(name, specialRules, bufConn, in)
	case socks5.Version:
		HandleSocks5(name, specialRules, bufConn, in)
	default:
		conn.Close()
	}
}

func HandleSocks4(name, specialRules string, conn net.Conn, in chan<- C.ConnContext) {
	addr, _, err := socks4.ServerHandshake(conn, authStore.Authenticator())
	if err != nil {
		conn.Close()
		return
	}
	in <- inbound.NewSocketWithInfos(socks5.ParseAddr(addr), conn, C.SOCKS4, name, specialRules)
}

func HandleSocks5(name, specialRules string, conn net.Conn, in chan<- C.ConnContext) {
	target, command, err := socks5.ServerHandshake(conn, authStore.Authenticator())
	if err != nil {
		conn.Close()
		return
	}
	if command == socks5.CmdUDPAssociate {
		defer conn.Close()
		io.Copy(io.Discard, conn)
		return
	}
	in <- inbound.NewSocketWithInfos(target, conn, C.SOCKS5, name, specialRules)
}
