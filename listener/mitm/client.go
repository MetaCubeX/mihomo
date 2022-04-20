package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

func newClient(source net.Addr, userAgent string, in chan<- C.ConnContext) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// excepted HTTP/2
			TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
			// from http.DefaultTransport
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				GetClientCertificate: func(info *tls.CertificateRequestInfo) (certificate *tls.Certificate, e error) {
					return nil, ErrCertUnsupported
				},
			},
			DialContext: func(context context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" && network != "tcp4" && network != "tcp6" {
					return nil, errors.New("unsupported network " + network)
				}

				dstAddr := socks5.ParseAddr(address)
				if dstAddr == nil {
					return nil, socks5.ErrAddressNotSupported
				}

				left, right := net.Pipe()

				in <- inbound.NewMitm(dstAddr, source, userAgent, right)

				return left, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 120 * time.Second,
	}
}
