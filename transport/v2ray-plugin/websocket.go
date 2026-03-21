package obfs

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

// Option is options of websocket obfs
type Option struct {
	Host                     string
	Port                     string
	Path                     string
	Headers                  map[string]string
	TLS                      bool
	ECHConfig                *ech.Config
	SkipCertVerify           bool
	Fingerprint              string
	Certificate              string
	PrivateKey               string
	Mux                      bool
	V2rayHttpUpgrade         bool
	V2rayHttpUpgradeFastOpen bool
}

// NewV2rayObfs return a HTTPObfs
func NewV2rayObfs(ctx context.Context, conn net.Conn, option *Option) (net.Conn, error) {
	header := http.Header{}
	for k, v := range option.Headers {
		header.Add(k, v)
	}

	config := &vmess.WebsocketConfig{
		Host:                     option.Host,
		Port:                     option.Port,
		Path:                     option.Path,
		V2rayHttpUpgrade:         option.V2rayHttpUpgrade,
		V2rayHttpUpgradeFastOpen: option.V2rayHttpUpgradeFastOpen,
		ECHConfig:                option.ECHConfig,
		Headers:                  header,
	}

	var err error
	if option.TLS {
		config.TLS = true
		config.TLSConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				ServerName:         option.Host,
				InsecureSkipVerify: option.SkipCertVerify,
				NextProtos:         []string{"http/1.1"},
			},
			Fingerprint: option.Fingerprint,
			Certificate: option.Certificate,
			PrivateKey:  option.PrivateKey,
		})
		if err != nil {
			return nil, err
		}

		if host := config.Headers.Get("Host"); host != "" {
			config.TLSConfig.ServerName = host
		}
	}

	conn, err = vmess.StreamWebsocketConn(ctx, conn, config)
	if err != nil {
		return nil, err
	}

	if option.Mux {
		conn = NewMux(conn, MuxOption{
			ID:   [2]byte{0, 0},
			Host: "127.0.0.1",
			Port: 0,
		})
	}
	return conn, nil
}
