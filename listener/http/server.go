package http

import (
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
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
	return NewWithAuthenticator(addr, tunnel, authStore.Authenticator, additions...)
}

// NewWithAuthenticate
// never change type traits because it's used in CMFA
func NewWithAuthenticate(addr string, tunnel C.Tunnel, authenticate bool, additions ...inbound.Addition) (*Listener, error) {
	getAuth := authStore.Authenticator
	if !authenticate {
		getAuth = authStore.Nil
	}
	return NewWithAuthenticator(addr, tunnel, getAuth, additions...)
}

func NewWithAuthenticator(addr string, tunnel C.Tunnel, getAuth func() auth.Authenticator, additions ...inbound.Addition) (*Listener, error) {
	isDefault := false
	if len(additions) == 0 {
		isDefault = true
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-HTTP"),
			inbound.WithSpecialRules(""),
		}
	}

	l, err := inbound.Listen("tcp", addr)
	if err != nil {
		return nil, err
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

			getAuth := getAuth
			if isDefault { // only apply on default listener
				if !inbound.IsRemoteAddrDisAllowed(conn.RemoteAddr()) {
					_ = conn.Close()
					continue
				}
				if inbound.SkipAuthRemoteAddr(conn.RemoteAddr()) {
					getAuth = authStore.Nil
				}
			}
			go HandleConn(conn, tunnel, getAuth, additions...)
		}
	}()

	return hl, nil
}
