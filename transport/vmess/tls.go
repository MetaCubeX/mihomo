package vmess

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	tlsC "github.com/metacubex/mihomo/component/tls"
)

type TLSConfig struct {
	Host              string
	SkipCertVerify    bool
	FingerPrint       string
	ClientFingerprint string
	NextProtos        []string
	Reality           *tlsC.RealityConfig
}

func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipCertVerify,
		NextProtos:         cfg.NextProtos,
	}

	var err error
	tlsConfig, err = ca.GetSpecifiedFingerprintTLSConfig(tlsConfig, cfg.FingerPrint)
	if err != nil {
		return nil, err
	}

	if len(cfg.ClientFingerprint) != 0 {
		if cfg.Reality == nil {
			utlsConn, valid := GetUTLSConn(conn, cfg.ClientFingerprint, tlsConfig)
			if valid {
				err := utlsConn.(*tlsC.UConn).HandshakeContext(ctx)
				return utlsConn, err
			}
		} else {
			return tlsC.GetRealityConn(ctx, conn, cfg.ClientFingerprint, tlsConfig, cfg.Reality)
		}
	}
	if cfg.Reality != nil {
		return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
	}

	tlsConn := tls.Client(conn, tlsConfig)

	err = tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}

func GetUTLSConn(conn net.Conn, ClientFingerprint string, tlsConfig *tls.Config) (net.Conn, bool) {

	if fingerprint, exists := tlsC.GetFingerprint(ClientFingerprint); exists {
		utlsConn := tlsC.UClient(conn, tlsConfig, fingerprint)

		return utlsConn, true
	}

	return nil, false
}
