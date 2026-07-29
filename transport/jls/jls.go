package jls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/ntp"

	tls "github.com/metacubex/jls-tls"
)

const (
	Mode                   = "jls"
	bitsPerByte            = 8
	rateLimitCycle         = 10 * time.Millisecond
	maxRateLimitBurstBytes = 64 * 1024
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
	upstream = newRateLimitedConn(upstream, config.RateLimit)
	if err = N.RelayContext(ctx, inbound, upstream); err != nil {
		return err
	}
	return ErrFallbackCompleted
}

type rateLimitedConn struct {
	net.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	readLimiter  *bitRateLimiter
	writeLimiter *bitRateLimiter
	burst        int
}

func newRateLimitedConn(conn net.Conn, rateBps uint64) net.Conn {
	if rateBps == 0 {
		return conn
	}
	burst := rateBps / bitsPerByte / uint64(time.Second/rateLimitCycle)
	if burst == 0 {
		burst = 1
	} else if burst > maxRateLimitBurstBytes {
		burst = maxRateLimitBurstBytes
	}
	limitCtx, cancel := context.WithCancel(context.Background())
	return &rateLimitedConn{
		Conn:         conn,
		ctx:          limitCtx,
		cancel:       cancel,
		readLimiter:  &bitRateLimiter{rateBps: rateBps},
		writeLimiter: &bitRateLimiter{rateBps: rateBps},
		burst:        int(burst),
	}
}

func (c *rateLimitedConn) Read(p []byte) (n int, err error) {
	if len(p) > c.burst {
		p = p[:c.burst]
	}
	n, err = c.Conn.Read(p)
	if n > 0 {
		if limitErr := c.readLimiter.WaitN(c.ctx, n); err == nil {
			err = limitErr
		}
	}
	return
}

func (c *rateLimitedConn) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > c.burst {
			chunkSize = c.burst
		}
		if err = c.writeLimiter.WaitN(c.ctx, chunkSize); err != nil {
			return n, err
		}
		var written int
		written, err = c.Conn.Write(p[:chunkSize])
		n += written
		p = p[written:]
		if err != nil {
			return n, err
		}
		if written != chunkSize {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}

func (c *rateLimitedConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

func (c *rateLimitedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}

type bitRateLimiter struct {
	mu      sync.Mutex
	rateBps uint64
	next    time.Time
}

func (l *bitRateLimiter) WaitN(ctx context.Context, n int) error {
	delay := l.reserveN(time.Now(), n)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *bitRateLimiter) reserveN(now time.Time, n int) time.Duration {
	interval := time.Duration(uint64(n) * bitsPerByte * uint64(time.Second) / l.rateBps)

	l.mu.Lock()
	ready := l.next
	if ready.Before(now) {
		ready = now
	}
	l.next = ready.Add(interval)
	l.mu.Unlock()
	return ready.Sub(now)
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
