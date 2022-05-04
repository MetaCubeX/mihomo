// Modified from: https://github.com/Qv2ray/gun-lite
// License: MIT

package gun

import (
	"crypto/tls"
	"fmt"
	"net"

	xtls "github.com/xtls/go"
	"golang.org/x/net/http2"
)

func NewHTTP2XTLSClient(dialFn DialFn, tlsConfig *tls.Config) *TransportWrap {
	wrap := TransportWrap{}
	dialFunc := func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		pconn, err := dialFn(network, addr)
		if err != nil {
			return nil, err
		}

		wrap.remoteAddr = pconn.RemoteAddr()
		xtlsConfig := &xtls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			ServerName:         cfg.ServerName,
		}

		cn := xtls.Client(pconn, xtlsConfig)
		if err := cn.Handshake(); err != nil {
			pconn.Close()
			return nil, err
		}
		state := cn.ConnectionState()
		if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
			cn.Close()
			return nil, fmt.Errorf("http2: unexpected ALPN protocol %s, want %s", p, http2.NextProtoTLS)
		}
		return cn, nil
	}

	wrap.Transport = &http2.Transport{
		DialTLS:            dialFunc,
		TLSClientConfig:    tlsConfig,
		AllowHTTP:          false,
		DisableCompression: true,
		PingTimeout:        0,
	}

	return &wrap
}

func StreamGunWithXTLSConn(conn net.Conn, tlsConfig *tls.Config, cfg *Config) (net.Conn, error) {
	dialFn := func(network, addr string) (net.Conn, error) {
		return conn, nil
	}

	transport := NewHTTP2XTLSClient(dialFn, tlsConfig)
	return StreamGunWithTransport(transport, cfg)
}
