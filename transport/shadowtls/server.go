package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/log"
)

var ErrFallbackCompleted = errors.New("shadow-tls: connection relayed to fallback")

type WildcardSNI int

const (
	WildcardSNIOff WildcardSNI = iota
	WildcardSNIAuthed
	WildcardSNIAll
)

type User struct {
	Name     string
	Password string
}

type HandshakeConfig struct {
	Server      string
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

type ServerConfig struct {
	version                int
	password               string // for protocol version 2
	users                  []User // for protocol version 3
	handshake              HandshakeConfig
	handshakeForServerName map[string]HandshakeConfig // for protocol version 2/3
	strictMode             bool                       // for protocol version 3
	wildcardSNI            WildcardSNI                // for protocol version 3
}

func NewServerConfig(
	version int,
	password string,
	users []User,
	handshake HandshakeConfig,
	handshakeForServerName map[string]HandshakeConfig,
	strictMode bool,
	wildcardSNI WildcardSNI,
) (*ServerConfig, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	if version == 3 && len(users) == 0 {
		return nil, errors.New("shadow-tls: at least one user is required")
	}
	if wildcardSNI < WildcardSNIOff || wildcardSNI > WildcardSNIAll {
		return nil, errors.New("shadow-tls: invalid wildcard SNI mode")
	}
	if !handshake.valid() && wildcardSNI == WildcardSNIOff {
		return nil, errors.New("shadow-tls: missing default handshake information")
	}
	if version < 3 && !handshake.valid() {
		return nil, errors.New("shadow-tls: missing default handshake information")
	}
	for serverName, handshakeConfig := range handshakeForServerName {
		if serverName == "" || !handshakeConfig.valid() {
			return nil, fmt.Errorf("shadow-tls: invalid handshake for server name %q", serverName)
		}
	}
	return &ServerConfig{
		version:                version,
		password:               password,
		users:                  append([]User(nil), users...),
		handshake:              handshake,
		handshakeForServerName: cloneHandshakeMap(handshakeForServerName),
		strictMode:             strictMode,
		wildcardSNI:            wildcardSNI,
	}, nil
}

func Server(ctx context.Context, conn net.Conn, config *ServerConfig) (net.Conn, error) {
	if conn == nil || config == nil {
		return nil, errors.New("shadow-tls: nil connection or server config")
	}
	var (
		serverConn net.Conn
		user       string
		err        error
	)
	switch config.version {
	case 1:
		serverConn, user, err = config.serverV1(ctx, conn)
	case 2:
		serverConn, user, err = config.serverV2(ctx, conn)
	case 3:
		serverConn, user, err = config.serverV3(ctx, conn)
	default:
		panic("unreachable")
	}
	if err != nil || user == "" {
		return serverConn, err
	}
	return &authenticatedConn{Conn: serverConn, user: user}, nil
}

func (s *ServerConfig) serverV1(ctx context.Context, conn net.Conn) (net.Conn, string, error) {
	handshakeConn, err := s.handshake.dial(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("shadow-tls: dial handshake server: %w", err)
	}
	defer handshakeConn.Close()
	if err = relayHandshake(conn, handshakeConn); err != nil {
		return nil, "", fmt.Errorf("shadow-tls: relay handshake: %w", err)
	}
	log.Debugln("[ShadowTLS] handshake finished")
	return conn, "", nil
}

func (s *ServerConfig) serverV2(ctx context.Context, conn net.Conn) (net.Conn, string, error) {
	clientHello, err := readFrame(conn)
	if err != nil {
		return nil, "", fmt.Errorf("shadow-tls: read client handshake: %w", err)
	}
	handshakeConfig := s.selectHandshake(clientHello)
	handshakeConn, err := handshakeConfig.dial(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("shadow-tls: dial handshake server: %w", err)
	}
	hashConn := newHashWriteConn(conn, s.password)
	serverCopyDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(hashConn, handshakeConn)
		serverCopyDone <- copyErr
	}()

	request, err := copyUntilHandshakeFinishedV2(
		handshakeConn,
		N.NewCachedConn(conn, clientHello),
		hashConn,
		2,
	)
	if err == nil {
		log.Debugln("[ShadowTLS] handshake finished")
		_ = handshakeConn.Close()
		<-serverCopyDone
		return N.NewCachedConn(newConn(conn), request), "", nil
	}
	if errors.Is(err, os.ErrPermission) {
		log.Warnln("[ShadowTLS] fallback connection")
		hashConn.Fallback()
		clientCopyDone := make(chan error, 1)
		go func() {
			_, copyErr := io.Copy(handshakeConn, conn)
			clientCopyDone <- copyErr
		}()
		var clientCopyErr, serverCopyErr error
		select {
		case clientCopyErr = <-clientCopyDone:
			finishCopyDirection(handshakeConn, conn, clientCopyErr)
			serverCopyErr = <-serverCopyDone
		case serverCopyErr = <-serverCopyDone:
			finishCopyDirection(conn, handshakeConn, serverCopyErr)
			clientCopyErr = <-clientCopyDone
		}
		_ = handshakeConn.Close()
		if relayErr := joinCopyErrors(clientCopyErr, serverCopyErr); relayErr != nil {
			return nil, "", relayErr
		}
		return nil, "", ErrFallbackCompleted
	}
	_ = handshakeConn.Close()
	<-serverCopyDone
	return nil, "", err
}

func (s *ServerConfig) serverV3(ctx context.Context, conn net.Conn) (net.Conn, string, error) {
	clientHello, err := readFrame(conn)
	if err != nil {
		return nil, "", fmt.Errorf("shadow-tls: read client handshake: %w", err)
	}
	serverName, err := extractServerName(clientHello)
	if err != nil {
		return nil, "", fmt.Errorf("shadow-tls: extract server name: %w", err)
	}
	user, authErr := verifyClientHello(clientHello, s.users)
	handshakeConfig := s.selectV3Handshake(serverName, authErr == nil)
	if authErr != nil {
		log.Warnln("[ShadowTLS] client hello verify failed: %v", authErr)
		return nil, "", s.relayFallback(ctx, conn, clientHello, handshakeConfig)
	}
	log.Debugln("[ShadowTLS] client hello verify success")

	handshakeConn, err := handshakeConfig.dial(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("shadow-tls: dial handshake server: %w", err)
	}
	defer handshakeConn.Close()
	if _, err = handshakeConn.Write(clientHello); err != nil {
		return nil, "", fmt.Errorf("shadow-tls: write client handshake: %w", err)
	}
	serverHello, err := readFrame(handshakeConn)
	if err != nil {
		return nil, "", fmt.Errorf("shadow-tls: read server handshake: %w", err)
	}
	if _, err = conn.Write(serverHello); err != nil {
		return nil, "", fmt.Errorf("shadow-tls: write server handshake: %w", err)
	}
	serverRandom := extractServerRandom(serverHello)
	if serverRandom == nil {
		log.Warnln("[ShadowTLS] server random extract failed, will copy bidirectional")
		if err = N.RelayContext(ctx, conn, handshakeConn); err != nil {
			return nil, "", err
		}
		return nil, "", ErrFallbackCompleted
	}
	if s.strictMode && !isServerHelloSupportTLS13(serverHello) {
		log.Warnln("[ShadowTLS] TLS 1.3 is not supported, will copy bidirectional")
		if err = N.RelayContext(ctx, conn, handshakeConn); err != nil {
			return nil, "", err
		}
		return nil, "", ErrFallbackCompleted
	}
	if log.Level() == log.DEBUG {
		log.Debugln("[ShadowTLS] client authenticated, server random extracted: %s", hex.EncodeToString(serverRandom))
	}

	hmacWrite := hmac.New(sha1.New, []byte(user.Password))
	_, _ = hmacWrite.Write(serverRandom)
	hmacAdd := hmac.New(sha1.New, []byte(user.Password))
	_, _ = hmacAdd.Write(serverRandom)
	_, _ = hmacAdd.Write([]byte("S"))
	hmacVerify := hmac.New(sha1.New, []byte(user.Password))
	resetVerify := func() { hmacReset(hmacVerify, serverRandom, 'C') }
	request, err := relayV3Handshake(conn, handshakeConn, user.Password, serverRandom, hmacWrite, hmacVerify, resetVerify)
	if err != nil {
		return nil, "", fmt.Errorf("shadow-tls: relay handshake: %w", err)
	}
	log.Debugln("[ShadowTLS] handshake relay finished")
	return N.NewCachedConn(newVerifiedConn(conn, hmacAdd, hmacVerify, nil), request), user.Name, nil
}

func (s *ServerConfig) relayFallback(ctx context.Context, conn net.Conn, prefix []byte, handshakeConfig HandshakeConfig) error {
	handshakeConn, err := handshakeConfig.dial(ctx)
	if err != nil {
		return fmt.Errorf("shadow-tls: dial fallback server: %w", err)
	}
	if err = N.RelayContext(ctx, N.NewCachedConn(conn, prefix), handshakeConn); err != nil {
		return err
	}
	return ErrFallbackCompleted
}

func (s *ServerConfig) selectHandshake(clientHello []byte) HandshakeConfig {
	serverName, err := extractServerName(clientHello)
	if err == nil {
		if custom, found := s.handshakeForServerName[serverName]; found {
			return custom
		}
	}
	return s.handshake
}

func (s *ServerConfig) selectV3Handshake(serverName string, authenticated bool) HandshakeConfig {
	if custom, found := s.handshakeForServerName[serverName]; found {
		return custom
	}
	handshakeConfig := s.handshake
	if s.wildcardSNI == WildcardSNIAll || (authenticated && s.wildcardSNI == WildcardSNIAuthed) {
		handshakeConfig.Server = net.JoinHostPort(serverName, "443")
	}
	return handshakeConfig
}

type authenticatedConn struct {
	net.Conn
	user string
}

func (c *authenticatedConn) Upstream() any { return c.Conn }

func UserFromConn(conn net.Conn) (string, bool) {
	authenticated, ok := N.FindUpstream[*authenticatedConn](conn, nil)
	if !ok {
		return "", false
	}
	return authenticated.user, true
}

func (c HandshakeConfig) valid() bool {
	return c.Server != "" && c.DialContext != nil
}

func (c HandshakeConfig) dial(ctx context.Context) (net.Conn, error) {
	if !c.valid() {
		return nil, errors.New("shadow-tls: missing handshake information")
	}
	return c.DialContext(ctx, "tcp", c.Server)
}

func cloneHandshakeMap(source map[string]HandshakeConfig) map[string]HandshakeConfig {
	if source == nil {
		return nil
	}
	cloned := make(map[string]HandshakeConfig, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func relayHandshake(clientConn, serverConn net.Conn) error {
	type result struct {
		err error
	}
	results := make(chan result, 2)
	go func() {
		results <- result{err: copyUntilHandshakeFinished(serverConn, clientConn)}
	}()
	go func() {
		results <- result{err: copyUntilHandshakeFinished(clientConn, serverConn)}
	}()
	first := <-results
	if first.err != nil {
		_ = clientConn.SetDeadline(time.Now())
		_ = serverConn.Close()
	}
	second := <-results
	if first.err != nil {
		return first.err
	}
	return second.err
}

func relayV3Handshake(clientConn, serverConn net.Conn, password string, serverRandom []byte, hmacWrite, hmacVerify hash.Hash, resetVerify func()) ([]byte, error) {
	type result struct {
		request []byte
		client  bool
		err     error
	}
	results := make(chan result, 2)
	go func() {
		request, err := copyByFrameUntilHMACMatches(clientConn, serverConn, hmacVerify, resetVerify)
		results <- result{request: request, client: true, err: err}
	}()
	go func() {
		err := copyByFrameWithModification(serverConn, clientConn, password, serverRandom, hmacWrite)
		results <- result{err: err}
	}()
	first := <-results
	if first.client && first.err == nil {
		_ = serverConn.Close()
		<-results
		return first.request, nil
	}
	_ = serverConn.Close()
	_ = clientConn.SetDeadline(time.Now())
	second := <-results
	if first.err != nil {
		return nil, first.err
	}
	return nil, second.err
}

func finishCopyDirection(dst, src net.Conn, err error) {
	if err == nil {
		closeWrite(dst)
		return
	}
	_ = dst.Close()
	_ = src.Close()
}

func closeWrite(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
		return
	}
	_ = conn.Close()
}

func joinCopyErrors(copyErrors ...error) error {
	var result error
	for _, err := range copyErrors {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if strings.Contains(err.Error(), "use of closed network connection") {
			continue
		}
		result = errors.Join(result, err)
	}
	return result
}
