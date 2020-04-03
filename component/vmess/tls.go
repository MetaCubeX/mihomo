package vmess

import (
	"crypto/tls"
	"net"
)

type TLSConfig struct {
	Host           string
	SkipCertVerify bool
	SessionCache   tls.ClientSessionCache
}

func StreamTLSConn(conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipCertVerify,
		ClientSessionCache: cfg.SessionCache,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	err := tlsConn.Handshake()
	return tlsConn, err
}
