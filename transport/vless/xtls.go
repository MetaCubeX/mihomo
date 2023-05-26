package vless

import (
	"context"
	"net"

	tlsC "github.com/Dreamacro/clash/component/tls"
	xtls "github.com/xtls/go"
)

type XTLSConfig struct {
	Host           string
	SkipCertVerify bool
	Fingerprint    string
	NextProtos     []string
}

func StreamXTLSConn(ctx context.Context, conn net.Conn, cfg *XTLSConfig) (net.Conn, error) {
	xtlsConfig := &xtls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipCertVerify,
		NextProtos:         cfg.NextProtos,
	}
	if len(cfg.Fingerprint) == 0 {
		xtlsConfig = tlsC.GetGlobalXTLSConfig(xtlsConfig)
	} else {
		var err error
		if xtlsConfig, err = tlsC.GetSpecifiedFingerprintXTLSConfig(xtlsConfig, cfg.Fingerprint); err != nil {
			return nil, err
		}
	}

	xtlsConn := xtls.Client(conn, xtlsConfig)

	err := xtlsConn.HandshakeContext(ctx)
	return xtlsConn, err
}
