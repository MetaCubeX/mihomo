package vmess

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	tlsC "github.com/Dreamacro/clash/component/tls"
	C "github.com/Dreamacro/clash/constant"
)

type TLSConfig struct {
	Host              string
	SkipCertVerify    bool
	FingerPrint       string
	ClientFingerprint string
	NextProtos        []string
	Reality           *tlsC.RealityConfig
}

func StreamTLSConn(conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipCertVerify,
		NextProtos:         cfg.NextProtos,
	}

	if len(cfg.FingerPrint) == 0 {
		tlsConfig = tlsC.GetGlobalTLSConfig(tlsConfig)
	} else {
		var err error
		if tlsConfig, err = tlsC.GetSpecifiedFingerprintTLSConfig(tlsConfig, cfg.FingerPrint); err != nil {
			return nil, err
		}
	}

	if len(cfg.ClientFingerprint) != 0 {
		if cfg.Reality == nil {
			utlsConn, valid := GetUTLSConn(conn, cfg.ClientFingerprint, tlsConfig)
			if valid {
				ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
				defer cancel()

				err := utlsConn.(*tlsC.UConn).HandshakeContext(ctx)
				return utlsConn, err
			}
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
			defer cancel()
			return tlsC.GetRealityConn(ctx, conn, cfg.ClientFingerprint, tlsConfig, cfg.Reality)
		}
	}
	if cfg.Reality != nil {
		return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
	}

	tlsConn := tls.Client(conn, tlsConfig)

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()

	err := tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}

func GetUTLSConn(conn net.Conn, ClientFingerprint string, tlsConfig *tls.Config) (net.Conn, bool) {

	if fingerprint, exists := tlsC.GetFingerprint(ClientFingerprint); exists {
		utlsConn := tlsC.UClient(conn, tlsConfig, fingerprint)

		return utlsConn, true
	}

	return nil, false
}
