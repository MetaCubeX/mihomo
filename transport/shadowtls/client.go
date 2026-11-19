package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/tls"
	"golang.org/x/exp/slices"
)

const Mode = "shadow-tls"

var (
	DefaultALPN = []string{"h2", "http/1.1"}
	WsALPN      = []string{"http/1.1"}
)

type TLSSessionIDGeneratorFunc func(clientHello []byte, sessionID []byte) error

type TLSHandshakeFunc func(
	ctx context.Context,
	conn net.Conn,
	sessionIDGenerator TLSSessionIDGeneratorFunc, // for shadow-tls version 3
) error

type ShadowTLSOption struct {
	Password          string
	Host              string
	Fingerprint       string
	Certificate       string
	PrivateKey        string
	ClientFingerprint string
	SkipCertVerify    bool
	NameCertVerify    string
	Version           int
	ALPN              []string
}

type Config struct {
	Password string
	Version  int
}

func NewConfig(password string, version int) (*Config, error) {
	if version == 0 {
		version = 2
	}
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	return &Config{
		Password: password,
		Version:  version,
	}, nil
}

type ClientConfig struct {
	Version      int
	Password     string
	StrictMode   bool
	TLSHandshake TLSHandshakeFunc
}

type Client struct {
	version      int
	password     string
	strictMode   bool
	tlsHandshake TLSHandshakeFunc
}

func NewClient(config ClientConfig) (*Client, error) {
	if err := checkVersion(config.Version); err != nil {
		return nil, err
	}
	return &Client{
		version:      config.Version,
		password:     config.Password,
		strictMode:   config.StrictMode,
		tlsHandshake: config.TLSHandshake,
	}, nil
}

func (c *Client) SetHandshakeFunc(handshakeFunc TLSHandshakeFunc) {
	c.tlsHandshake = handshakeFunc
}

func (c *Client) DialContextConn(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if conn == nil || c.tlsHandshake == nil {
		return nil, errors.New("shadow-tls: connection and TLS handshake are required")
	}
	switch c.version {
	case 1:
		if err := c.tlsHandshake(ctx, conn, nil); err != nil {
			return nil, err
		}
		log.Debugln("[ShadowTLS] client handshake finished")
		return conn, nil
	case 2:
		hashConn := newHashReadConn(conn, c.password)
		if err := c.tlsHandshake(ctx, hashConn, nil); err != nil {
			return nil, err
		}
		log.Debugln("[ShadowTLS] client handshake finished")
		return newClientConn(hashConn), nil
	case 3:
		stream := newStreamWrapper(conn, c.password)
		if err := c.tlsHandshake(ctx, stream, generateSessionID(c.password)); err != nil {
			return nil, err
		}
		log.Debugln("[ShadowTLS] handshake success")
		isTLS13, authorized, serverRandom, readHMAC := stream.Authorized()
		if c.strictMode && !isTLS13 {
			return nil, errors.New("shadow-tls: TLS 1.3 is not supported")
		}
		if !authorized {
			return nil, errors.New("shadow-tls: traffic hijacked")
		}
		if log.Level() == log.DEBUG {
			log.Debugln("[ShadowTLS] authorized, server random extracted: %s", hex.EncodeToString(serverRandom))
		}
		hmacAdd := hmac.New(sha1.New, []byte(c.password))
		_, _ = hmacAdd.Write(serverRandom)
		_, _ = hmacAdd.Write([]byte("C"))
		hmacVerify := hmac.New(sha1.New, []byte(c.password))
		_, _ = hmacVerify.Write(serverRandom)
		_, _ = hmacVerify.Write([]byte("S"))
		return newVerifiedConn(conn, hmacAdd, hmacVerify, readHMAC), nil
	default:
		panic("unreachable")
	}
}

func NewShadowTLS(ctx context.Context, conn net.Conn, option *ShadowTLSOption) (net.Conn, error) {
	if option == nil {
		return nil, errors.New("shadow-tls: nil client option")
	}
	if err := checkVersion(option.Version); err != nil {
		return nil, err
	}
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			NextProtos:         append([]string(nil), option.ALPN...),
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: option.SkipCertVerify,
			ServerName:         option.Host,
		},
		Fingerprint:    option.Fingerprint,
		NameCertVerify: option.NameCertVerify,
		Certificate:    option.Certificate,
		PrivateKey:     option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}
	if option.Version == 1 {
		tlsConfig.MaxVersion = tls.VersionTLS12 // ShadowTLS v1 only support TLS 1.2
	}
	client, err := NewClient(ClientConfig{
		Version:      option.Version,
		Password:     option.Password,
		TLSHandshake: uTLSHandshakeFunc(tlsConfig, option.ClientFingerprint, option.Version),
	})
	if err != nil {
		return nil, err
	}
	return client.DialContextConn(ctx, conn)
}

func uTLSHandshakeFunc(config *tls.Config, clientFingerprint string, version int) TLSHandshakeFunc {
	return func(ctx context.Context, conn net.Conn, sessionIDGenerator TLSSessionIDGeneratorFunc) error {
		tlsConfig := tlsC.UConfig(config)
		tlsConfig.SessionIDGenerator = sessionIDGenerator
		if version == 1 {
			tlsConfig.MaxVersion = tlsC.VersionTLS12 // ShadowTLS v1 only support TLS 1.2
			return tlsC.Client(conn, tlsConfig).HandshakeContext(ctx)
		}
		if fingerprint, ok := tlsC.GetFingerprint(clientFingerprint); ok {
			tlsConn := tlsC.UClient(conn, tlsConfig, fingerprint)
			if slices.Equal(tlsConfig.NextProtos, WsALPN) {
				if err := tlsC.BuildWebsocketHandshakeState(tlsConn); err != nil {
					return err
				}
			}
			return tlsConn.HandshakeContext(ctx)
		}
		return tlsC.Client(conn, tlsConfig).HandshakeContext(ctx)
	}
}

func checkVersion(version int) error {
	if version < 1 || version > 3 {
		return fmt.Errorf("shadow-tls: unknown protocol version: %d", version)
	}
	return nil
}
