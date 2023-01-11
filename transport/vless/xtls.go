package vless

import (
	"context"
	tlsC "github.com/Dreamacro/clash/component/tls"
	"net"

	C "github.com/Dreamacro/clash/constant"
	xtls "github.com/xtls/go"
)

type XTLSConfig struct {
	Host           string
	SkipCertVerify bool
	Fingerprint    string
	NextProtos     []string
}

func StreamXTLSConn(conn net.Conn, cfg *XTLSConfig) (net.Conn, error) {
	xtlsConfig := &xtls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipCertVerify,
		NextProtos:         cfg.NextProtos,
	}
	if len(cfg.Fingerprint) == 0 {
		xtlsConfig = tlsC.GetGlobalFingerprintXTLCConfig(xtlsConfig)
	} else {
		var err error
		if xtlsConfig, err = tlsC.GetSpecifiedFingerprintXTLSConfig(xtlsConfig, cfg.Fingerprint); err != nil {
			return nil, err
		}
	}

	xtlsConn := xtls.Client(conn, xtlsConfig)

	// fix xtls handshake not timeout
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	err := xtlsConn.HandshakeContext(ctx)
	return xtlsConn, err
}
