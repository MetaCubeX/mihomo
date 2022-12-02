package vmess

import (
	"context"
	"crypto/tls"
	tlsC "github.com/Dreamacro/clash/component/tls"
	"net"

	C "github.com/Dreamacro/clash/constant"
)

type TLSConfig struct {
	Host           string
	SkipCertVerify bool
	FingerPrint    string
	NextProtos     []string
}

func StreamTLSConn(conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipCertVerify,
		NextProtos:         cfg.NextProtos,
	}

	if len(cfg.FingerPrint) == 0 {
		tlsConfig = tlsC.GetGlobalFingerprintTLCConfig(tlsConfig)
	} else {
		var err error
		if tlsConfig, err = tlsC.GetSpecifiedFingerprintTLSConfig(tlsConfig, cfg.FingerPrint); err != nil {
			return nil, err
		}
	}

	tlsConn := tls.Client(conn, tlsConfig)

	// fix tls handshake not timeout
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	err := tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}
