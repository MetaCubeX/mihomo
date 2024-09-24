package mixed

import (
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	"github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/socks"
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
	return NewWithAuthenticator(addr, tunnel, authStore.Authenticator, additions...)
}

func NewWithAuthenticator(addr string, tunnel C.Tunnel, getAuth func() auth.Authenticator, additions ...inbound.Addition) (*Listener, error) {
	isDefault := false
	if len(additions) == 0 {
		isDefault = true
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-MIXED"),
			inbound.WithSpecialRules(""),
		}
	}

	l, err := inbound.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	ml := &Listener{
		listener: l,
		addr:     addr,
	}
	go func() {
		for {
			c, err := ml.listener.Accept()
			if err != nil {
				if ml.closed {
					break
				}
				continue
			}
			getAuth := getAuth
			if isDefault { // only apply on default listener
				if !inbound.IsRemoteAddrDisAllowed(c.RemoteAddr()) {
					_ = c.Close()
					continue
				}
				if inbound.SkipAuthRemoteAddr(c.RemoteAddr()) {
					getAuth = authStore.Nil
				}
			}
			go handleConn(c, tunnel, getAuth, additions...)
		}
	}()

	return ml, nil
}

func handleConn(conn net.Conn, tunnel C.Tunnel, getAuth func() auth.Authenticator, additions ...inbound.Addition) {
	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		return
	}

	switch head[0] {
	case socks4.Version:
		socks.HandleSocks4(bufConn, tunnel, getAuth, additions...)
	case socks5.Version:
		socks.HandleSocks5(bufConn, tunnel, getAuth, additions...)
	default:
		http.HandleConn(bufConn, tunnel, getAuth, additions...)
	}
}
