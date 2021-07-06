package vless

import (
	"net"

	xtls "github.com/xtls/go"
)

type XTLSConfig struct {
	Host           string
	SkipCertVerify bool
	NextProtos     []string
}

func StreamXTLSConn(conn net.Conn, cfg *XTLSConfig) (net.Conn, error) {
	xtlsConfig := &xtls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipCertVerify,
		NextProtos:         cfg.NextProtos,
	}

	xtlsConn := xtls.Client(conn, xtlsConfig)
	err := xtlsConn.Handshake()
	return xtlsConn, err
}
