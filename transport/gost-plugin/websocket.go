package gost

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/transport/vmess"
	smux "github.com/sagernet/smux"
)

// Option is options of gost websocket
type Option struct {
	Host           string
	Port           string
	Path           string
	Headers        map[string]string
	TLS            bool
	SkipCertVerify bool
	Fingerprint    string
	Mux            bool
}

// muxConn is a wrapper around smux.Stream that also closes the session when closed
type muxConn struct {
	net.Conn
	session *smux.Session
}

func (m *muxConn) Close() error {
	streamErr := m.Conn.Close()
	sessionErr := m.session.Close()

	// Return stream error if there is one, otherwise return session error
	if streamErr != nil {
		return streamErr
	}
	return sessionErr
}

// NewGostWebsocket return a gost websocket
func NewGostWebsocket(ctx context.Context, conn net.Conn, option *Option) (net.Conn, error) {
	header := http.Header{}
	for k, v := range option.Headers {
		header.Add(k, v)
	}

	config := &vmess.WebsocketConfig{
		Host:    option.Host,
		Port:    option.Port,
		Path:    option.Path,
		Headers: header,
	}

	if option.TLS {
		config.TLS = true
		tlsConfig := &tls.Config{
			ServerName:         option.Host,
			InsecureSkipVerify: option.SkipCertVerify,
			NextProtos:         []string{"http/1.1"},
		}
		var err error
		config.TLSConfig, err = ca.GetSpecifiedFingerprintTLSConfig(tlsConfig, option.Fingerprint)
		if err != nil {
			return nil, err
		}

		if host := config.Headers.Get("Host"); host != "" {
			config.TLSConfig.ServerName = host
		}
	}

	var err error
	conn, err = vmess.StreamWebsocketConn(ctx, conn, config)
	if err != nil {
		return nil, err
	}

	if option.Mux {
		config := smux.DefaultConfig()
		config.KeepAliveDisabled = true

		session, err := smux.Client(conn, config)
		if err != nil {
			return nil, err
		}

		stream, err := session.OpenStream()
		if err != nil {
			session.Close()
			return nil, err
		}

		return &muxConn{
			Conn:    stream,
			session: session,
		}, nil
	}
	return conn, nil
}
