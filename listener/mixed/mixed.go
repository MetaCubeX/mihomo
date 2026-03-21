package mixed

import (
	"errors"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/socks4"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/tls"
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
	return NewWithConfig(LC.AuthServer{Enable: true, Listen: addr, AuthStore: authStore.Default}, tunnel, additions...)
}

func NewWithConfig(config LC.AuthServer, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	isDefault := false
	if len(additions) == 0 {
		isDefault = true
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-MIXED"),
			inbound.WithSpecialRules(""),
		}
	}

	l, err := inbound.Listen("tcp", config.Listen)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{Time: ntp.Now}
	var realityBuilder *reality.Builder

	if config.Certificate != "" && config.PrivateKey != "" {
		certLoader, err := ca.NewTLSKeyPairLoader(config.Certificate, config.PrivateKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certLoader()
		}

		if config.EchKey != "" {
			err = ech.LoadECHKey(config.EchKey, tlsConfig)
			if err != nil {
				return nil, err
			}
		}
	}
	tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(config.ClientAuthType)
	if len(config.ClientAuthCert) > 0 {
		if tlsConfig.ClientAuth == tls.NoClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		pool, err := ca.LoadCertificates(config.ClientAuthCert)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
	}
	if config.RealityConfig.PrivateKey != "" {
		if tlsConfig.GetCertificate != nil {
			return nil, errors.New("certificate is unavailable in reality")
		}
		if tlsConfig.ClientAuth != tls.NoClientCert {
			return nil, errors.New("client-auth is unavailable in reality")
		}
		realityBuilder, err = config.RealityConfig.Build(tunnel)
		if err != nil {
			return nil, err
		}
	}

	if realityBuilder != nil {
		l = realityBuilder.NewListener(l)
	} else if tlsConfig.GetCertificate != nil {
		l = tls.NewListener(l, tlsConfig)
	}

	ml := &Listener{
		listener: l,
		addr:     config.Listen,
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
			store := config.AuthStore
			if isDefault || store == authStore.Default { // only apply on default listener
				if !inbound.IsRemoteAddrDisAllowed(c.RemoteAddr()) {
					_ = c.Close()
					continue
				}
				if inbound.SkipAuthRemoteAddr(c.RemoteAddr()) {
					store = authStore.Nil
				}
			}
			go handleConn(c, tunnel, store, additions...)
		}
	}()

	return ml, nil
}

func handleConn(conn net.Conn, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		return
	}

	switch head[0] {
	case socks4.Version:
		socks.HandleSocks4(bufConn, tunnel, store, additions...)
	case socks5.Version:
		socks.HandleSocks5(bufConn, tunnel, store, additions...)
	default:
		http.HandleConn(bufConn, tunnel, store, additions...)
	}
}
