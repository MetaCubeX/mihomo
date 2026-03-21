package sing_shadowtls

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing-shadowtls"
	"github.com/metacubex/tls"
	"golang.org/x/exp/slices"
)

const (
	Mode string = "shadow-tls"
)

var (
	DefaultALPN = []string{"h2", "http/1.1"}
	WsALPN      = []string{"http/1.1"}
)

type ShadowTLSOption struct {
	Password          string
	Host              string
	Fingerprint       string
	Certificate       string
	PrivateKey        string
	ClientFingerprint string
	SkipCertVerify    bool
	Version           int
	ALPN              []string
}

func NewShadowTLS(ctx context.Context, conn net.Conn, option *ShadowTLSOption) (net.Conn, error) {
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			NextProtos:         option.ALPN,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: option.SkipCertVerify,
			ServerName:         option.Host,
		},
		Fingerprint: option.Fingerprint,
		Certificate: option.Certificate,
		PrivateKey:  option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}

	if option.Version == 1 {
		tlsConfig.MaxVersion = tls.VersionTLS12 // ShadowTLS v1 only support TLS 1.2
	}

	tlsHandshake := uTLSHandshakeFunc(tlsConfig, option.ClientFingerprint, option.Version)
	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:      option.Version,
		Password:     option.Password,
		TLSHandshake: tlsHandshake,
		Logger:       log.SingLogger,
	})
	if err != nil {
		return nil, err
	}
	return client.DialContextConn(ctx, conn)
}

func uTLSHandshakeFunc(config *tls.Config, clientFingerprint string, version int) shadowtls.TLSHandshakeFunc {
	return func(ctx context.Context, conn net.Conn, sessionIDGenerator shadowtls.TLSSessionIDGeneratorFunc) error {
		tlsConfig := tlsC.UConfig(config)
		tlsConfig.SessionIDGenerator = sessionIDGenerator
		if version == 1 {
			tlsConfig.MaxVersion = tlsC.VersionTLS12 // ShadowTLS v1 only support TLS 1.2
			tlsConn := tlsC.Client(conn, tlsConfig)
			return tlsConn.HandshakeContext(ctx)
		}
		if clientFingerprint, ok := tlsC.GetFingerprint(clientFingerprint); ok {
			tlsConn := tlsC.UClient(conn, tlsConfig, clientFingerprint)
			if slices.Equal(tlsConfig.NextProtos, WsALPN) {
				err := tlsC.BuildWebsocketHandshakeState(tlsConn)
				if err != nil {
					return err
				}
			}
			if version == 2 { // ShadowTLS v2 not work with X25519MLKEM768
				err := tlsC.BuildRemovedX25519MLKEM768HandshakeState(tlsConn)
				if err != nil {
					return err
				}
			}
			return tlsConn.HandshakeContext(ctx)
		}
		tlsConn := tlsC.Client(conn, tlsConfig)
		return tlsConn.HandshakeContext(ctx)
	}
}
