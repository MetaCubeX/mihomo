package jls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ratelimit"
	"github.com/metacubex/mihomo/ntp"

	tls "github.com/metacubex/jls-tls"
)

const (
	Mode = "jls"
)

var (
	DefaultALPN          = []string{"h2", "http/1.1"}
	ErrJLSAuthFailed     = tls.ErrJLSAuthFailed
	ErrFallbackCompleted = errors.New("jls: connection relayed to fallback")
)

type User = tls.JLSUser

type ClientConfig struct {
	Config

	ServerName        string
	ALPN              []string
	ClientFingerprint string
}

type Config struct {
	User User
}

type ServerConfig struct {
	TLSConfig   *tls.Config
	Dest        string
	RateLimit   uint64
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

func NewConfig(username, password string) (*Config, error) {
	if username == "" {
		return nil, errors.New("jls: username is required")
	}
	if password == "" {
		return nil, errors.New("jls: password is required")
	}
	return &Config{User: User{Username: username, Password: password}}, nil
}

func NewClientConfig(serverName, username, password string, alpn []string) (*ClientConfig, error) {
	if serverName == "" {
		return nil, errors.New("jls: server name is required")
	}
	authConfig, err := NewConfig(username, password)
	if err != nil {
		return nil, err
	}
	config := &ClientConfig{
		Config:     *authConfig,
		ServerName: serverName,
	}
	if alpn != nil {
		config.ALPN = append([]string{}, alpn...)
	}
	return config, nil
}

func NewClient(ctx context.Context, conn net.Conn, config *ClientConfig) (net.Conn, error) {
	if config == nil {
		return nil, errors.New("jls: nil client config")
	}
	if config.ServerName == "" {
		return nil, errors.New("jls: server name is required")
	}
	if config.User.Username == "" {
		return nil, errors.New("jls: username is required")
	}
	if config.User.Password == "" {
		return nil, errors.New("jls: password is required")
	}
	if client, ok, err := newUTLSClient(ctx, conn, config); ok {
		return client, err
	}
	alpn := config.ALPN
	if alpn == nil {
		alpn = DefaultALPN
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: config.ServerName,
		NextProtos: append([]string(nil), alpn...),
		RootCAs:    ca.GetCertPool(),
		Time:       ntp.Now,
		JLSConfig: &tls.JLSConfig{
			Enable: true,
			User:   config.User,
		},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if tlsConn.ConnectionState().JLS.Status != tls.JLSAuthenticated {
		return nil, ErrJLSAuthFailed
	}
	return tlsConn, nil
}

func NewServerConfig(sni, dest string, users []User, alpn []string, rateLimit uint64, dialContext func(context.Context, string, string) (net.Conn, error)) (*ServerConfig, error) {
	if dest == "" {
		return nil, errors.New("jls: dest is required")
	}
	destHost, _, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, fmt.Errorf("jls: invalid dest address: %w", err)
	}
	if sni == "" {
		sni = destHost
	}
	if len(users) == 0 {
		return nil, errors.New("jls: at least one user is required")
	}
	for _, user := range users {
		if user.Username == "" {
			return nil, errors.New("jls: username is required")
		}
		if user.Password == "" {
			return nil, errors.New("jls: password is required")
		}
	}
	if dialContext == nil {
		return nil, errors.New("jls: dial context is required")
	}
	if alpn == nil {
		alpn = DefaultALPN
	}
	// JLS authenticates the peer, so this generated certificate only carries the TLS handshake.
	certificatePEM, privateKeyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		return nil, fmt.Errorf("jls: generate TLS certificate: %w", err)
	}
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("jls: parse TLS certificate: %w", err)
	}
	return &ServerConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   append([]string(nil), alpn...),
			MinVersion:   tls.VersionTLS13,
			Time:         ntp.Now,
			JLSConfig: &tls.JLSConfig{
				Enable:     true,
				Users:      append([]User(nil), users...),
				ServerName: sni,
			},
		},
		Dest:        dest,
		RateLimit:   rateLimit,
		DialContext: dialContext,
	}, nil
}

func Server(ctx context.Context, conn net.Conn, config *ServerConfig) (net.Conn, error) {
	if config == nil || config.TLSConfig == nil {
		return nil, errors.New("jls: nil server config")
	}
	recorder := &handshakeRecorderConn{Conn: conn, recording: true}
	tlsConn := tls.Server(recorder, config.TLSConfig.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// A partial or complete server flight may have been written before a later
		// client message or network error; forwarding would then mix two TLS handshakes.
		if recorder.wroteToClient() {
			recorder.discard()
			return nil, err
		}
		return nil, relayFallback(ctx, conn, recorder.stop(), config)
	}
	recorder.discard()
	// Defensively reject a successful TLS handshake if custom configuration bypassed JLS authentication.
	if tlsConn.ConnectionState().JLS.Status != tls.JLSAuthenticated {
		return nil, ErrJLSAuthFailed
	}
	return tlsConn, nil
}

func UserFromConn(conn net.Conn) (string, bool) {
	tlsConn, ok := N.FindUpstream(conn, func(tlsConn *tls.Conn) bool {
		return tlsConn.ConnectionState().JLS.Status != tls.JLSDisabled
	})
	if !ok {
		return "", false
	}
	state := tlsConn.ConnectionState().JLS
	if state.Status != tls.JLSAuthenticated || state.User == "" {
		return "", false
	}
	return state.User, true
}

func relayFallback(ctx context.Context, inbound net.Conn, prefix []byte, config *ServerConfig) error {
	upstream, err := config.DialContext(ctx, "tcp", config.Dest)
	if err != nil {
		return err
	}
	inbound = N.NewCachedConn(inbound, prefix)
	upstream = ratelimit.NewRateLimitedConn(upstream, config.RateLimit)
	if err = N.RelayContext(ctx, inbound, upstream); err != nil {
		return err
	}
	return ErrFallbackCompleted
}


type handshakeRecorderConn struct {
	net.Conn
	buffer    bytes.Buffer
	recording bool
	wrote     bool
}

func (c *handshakeRecorderConn) Upstream() any {
	return c.Conn
}

func (c *handshakeRecorderConn) ReaderReplaceable() bool {
	return !c.recording
}

func (c *handshakeRecorderConn) WriterReplaceable() bool {
	return !c.recording
}

func (c *handshakeRecorderConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.recording && n > 0 {
		_, _ = c.buffer.Write(p[:n])
	}
	return n, err
}

func (c *handshakeRecorderConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.recording && n > 0 {
		c.wrote = true
	}
	return n, err
}

func (c *handshakeRecorderConn) stop() []byte {
	c.recording = false
	data := c.buffer.Bytes()
	// Transfer ownership of the backing slice to the fallback path. Recording is
	// disabled before detaching, so the recorder cannot append to or reuse it.
	c.buffer = bytes.Buffer{}
	return data
}

func (c *handshakeRecorderConn) discard() {
	c.recording = false
	c.buffer = bytes.Buffer{}
}

func (c *handshakeRecorderConn) wroteToClient() bool {
	return c.wrote
}
