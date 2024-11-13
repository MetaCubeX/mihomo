package socks

import (
	"io"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	"github.com/metacubex/mihomo/transport/socks4"
	"github.com/metacubex/mihomo/transport/socks5"
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

func New(addr string, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	return NewWithAuthenticator(addr, tunnel, authStore.Default, additions...)
}

func NewWithAuthenticator(addr string, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) (*Listener, error) {
	isDefault := false
	if len(additions) == 0 {
		isDefault = true
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-SOCKS"),
			inbound.WithSpecialRules(""),
		}
	}

	l, err := inbound.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	sl := &Listener{
		listener: l,
		addr:     addr,
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
			store := store
			if isDefault || store == authStore.Default { // only apply on default listener
				if !inbound.IsRemoteAddrDisAllowed(c.RemoteAddr()) {
					_ = c.Close()
					continue
				}
				if inbound.SkipAuthRemoteAddr(c.RemoteAddr()) {
					store = authStore.Nil
				}
			}
			go handleSocks(c, tunnel, store, additions...)
		}
	}()

	return sl, nil
}

func handleSocks(conn net.Conn, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	switch head[0] {
	case socks4.Version:
		HandleSocks4(bufConn, tunnel, store, additions...)
	case socks5.Version:
		HandleSocks5(bufConn, tunnel, store, additions...)
	default:
		conn.Close()
	}
}

func HandleSocks4(conn net.Conn, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	authenticator := store.Authenticator()
	addr, _, user, err := socks4.ServerHandshake(conn, authenticator)
	if err != nil {
		conn.Close()
		return
	}
	additions = append(additions, inbound.WithInUser(user))
	tunnel.HandleTCPConn(inbound.NewSocket(socks5.ParseAddr(addr), conn, C.SOCKS4, additions...))
}

func HandleSocks5(conn net.Conn, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	authenticator := store.Authenticator()
	target, command, user, err := socks5.ServerHandshake(conn, authenticator)
	if err != nil {
		conn.Close()
		return
	}
	if command == socks5.CmdUDPAssociate {
		defer conn.Close()
		io.Copy(io.Discard, conn)
		return
	}
	additions = append(additions, inbound.WithInUser(user))
	tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.SOCKS5, additions...))
}
