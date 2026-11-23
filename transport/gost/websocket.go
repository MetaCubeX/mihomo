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
	Host                 string
	Port                 string
	Path                 string
	Headers              map[string]string
	TLS                  bool
	ECHConfig            *ech.Config
	SkipCertVerify       bool
	NameCertVerify       string
	Fingerprint          string
	Certificate          string
	PrivateKey           string
	SNI                  string
	ClientFingerprint    string
	Mux                  bool
	MuxKeepAliveDisabled bool
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
		Host:              option.Host,
		Port:              option.Port,
		Path:              option.Path,
		ECHConfig:         option.ECHConfig,
		Headers:           header,
		ClientFingerprint: option.ClientFingerprint,
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
			Fingerprint:    option.Fingerprint,
			NameCertVerify: option.NameCertVerify,
			Certificate:    option.Certificate,
			PrivateKey:     option.PrivateKey,
		})
		if err != nil {
			return nil, err
		}

		if host := config.Headers.Get("Host"); host != "" {
			config.TLSConfig.ServerName = host
		}
		if option.SNI != "" {
			config.TLSConfig.ServerName = option.SNI
		}
	}

	conn, err = vmess.StreamWebsocketConn(ctx, conn, config)
	if err != nil {
		return nil, err
	}

	if option.Mux {
		// Keep the default smux v1 and keepalive settings aligned with GOST MWS.
		config := smux.DefaultConfig()
		config.KeepAliveDisabled = option.MuxKeepAliveDisabled

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
