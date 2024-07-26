package http

import (
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
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
	return NewWithAuthenticator(addr, tunnel, authStore.Authenticator(), additions...)
}

// NewWithAuthenticate
// never change type traits because it's used in CFMA
func NewWithAuthenticate(addr string, tunnel C.Tunnel, authenticate bool, additions ...inbound.Addition) (*Listener, error) {
	authenticator := authStore.Authenticator()
	if !authenticate {
		authenticator = nil
	}
	return NewWithAuthenticator(addr, tunnel, authenticator, additions...)
}

func NewWithAuthenticator(addr string, tunnel C.Tunnel, authenticator auth.Authenticator, additions ...inbound.Addition) (*Listener, error) {
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
			if features.CMFA {
				if t, ok := conn.(*net.TCPConn); ok {
					t.SetKeepAlive(false)
				}
			}
			if isDefault { // only apply on default listener
				if !inbound.IsRemoteAddrDisAllowed(conn.RemoteAddr()) {
					_ = conn.Close()
					continue
				}
			}
			go HandleConn(conn, tunnel, authenticator, additions...)
		}
	}()

	return hl, nil
}
