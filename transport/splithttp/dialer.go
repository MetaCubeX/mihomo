package splithttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
)

type Dialer struct {
	client *http.Client
	config *SplitHTTPConfig
}

func NewDialer(config *SplitHTTPConfig, tlsConfig *tls.Config) *Dialer {
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   tlsConfig,
	}
	return &Dialer{
		client: &http.Client{
			Transport: transport,
		},
		config: config,
	}
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented yet")
}
