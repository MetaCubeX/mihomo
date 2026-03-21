package gost

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/smux"
	"github.com/metacubex/tls"
)

// Option is options of gost websocket
type Option struct {
	Host           string
	Port           string
	Path           string
	Headers        map[string]string
	TLS            bool
	ECHConfig      *ech.Config
	SkipCertVerify bool
	Fingerprint    string
	Certificate    string
	PrivateKey     string
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
		Host:      option.Host,
		Port:      option.Port,
		Path:      option.Path,
		ECHConfig: option.ECHConfig,
		Headers:   header,
	}

	var err error
	if option.TLS {
		config.TLS = true
		config.TLSConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				ServerName:         option.Host,
				InsecureSkipVerify: option.SkipCertVerify,
				NextProtos:         []string{"http/1.1"},
			},
			Fingerprint: option.Fingerprint,
			Certificate: option.Certificate,
			PrivateKey:  option.PrivateKey,
		})
		if err != nil {
			return nil, err
		}

		if host := config.Headers.Get("Host"); host != "" {
			config.TLSConfig.ServerName = host
		}
	}

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
