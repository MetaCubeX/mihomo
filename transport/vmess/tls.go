package vmess

import (
	"context"
	"crypto/tls"
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
		utlsConn, valid := GetUtlsConnWithClientFingerprint(conn, cfg.ClientFingerprint, tlsConfig)
		if valid {
			ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
			defer cancel()

			err := utlsConn.(*tlsC.UConn).HandshakeContext(ctx)
			return utlsConn, err
		}
	}
	tlsConn := tls.Client(conn, tlsConfig)

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()

	err := tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}

func GetUtlsConnWithClientFingerprint(conn net.Conn, ClientFingerprint string, tlsConfig *tls.Config) (net.Conn, bool) {

	if fingerprint, exists := tlsC.GetFingerprint(ClientFingerprint); exists {
		utlsConn := tlsC.UClient(conn, tlsConfig, fingerprint)

		return utlsConn, true
	}

	return nil, false
}
