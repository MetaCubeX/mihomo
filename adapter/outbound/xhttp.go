package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	mihomoVMess "github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/metacubex/http"
	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

type XHTTPOptions struct {
	Path             string                 `proxy:"path,omitempty"`
	Host             string                 `proxy:"host,omitempty"`
	Mode             string                 `proxy:"mode,omitempty"`
	Headers          map[string]string      `proxy:"headers,omitempty"`
	NoGRPCHeader     bool                   `proxy:"no-grpc-header,omitempty"`
	XPaddingBytes    string                 `proxy:"x-padding-bytes,omitempty"`
	TryQUIC          *bool                  `proxy:"try-quic,omitempty"`
	DownloadSettings *XHTTPDownloadSettings `proxy:"download-settings,omitempty"`
}

type XHTTPDownloadSettings struct {
	Server            string            `proxy:"server,omitempty"`
	Port              int               `proxy:"port,omitempty"`
	TLS               *bool             `proxy:"tls,omitempty"`
	Headers           map[string]string `proxy:"headers,omitempty"`
	Host              string            `proxy:"host,omitempty"`
	Path              string            `proxy:"path,omitempty"`
	Mode              string            `proxy:"mode,omitempty"`
	ServerName        string            `proxy:"servername,omitempty"`
	ClientFingerprint string            `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify    bool              `proxy:"skip-cert-verify,omitempty"`
	RealityOpts       RealityOptions    `proxy:"reality-opts,omitempty"`
}

type SplitHTTPOptions = XHTTPOptions

type xhttpTLSOptions struct {
	Address           string
	TLSEnabled        bool
	ServerName        string
	SkipCertVerify    bool
	Fingerprint       string
	Certificate       string
	PrivateKey        string
	ClientFingerprint string
	ALPN              []string
	ECH               *ech.Config
	Reality           *tlsC.RealityConfig
}

func hasXHTTPOptions(option XHTTPOptions) bool {
	return option.Path != "" ||
		option.Host != "" ||
		option.Mode != "" ||
		len(option.Headers) != 0 ||
		option.NoGRPCHeader ||
		option.XPaddingBytes != "" ||
		option.TryQUIC != nil ||
		option.DownloadSettings != nil
}

func selectXHTTPOptions(network string, primary XHTTPOptions, compat SplitHTTPOptions) XHTTPOptions {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "splithttp":
		if hasXHTTPOptions(compat) {
			return compat
		}
		return primary
	case "xhttp":
		if hasXHTTPOptions(primary) {
			return primary
		}
		return compat
	default:
		if hasXHTTPOptions(primary) {
			return primary
		}
		return compat
	}
}

func normalizeXHTTPALPN(alpn []string) []string {
	if len(alpn) == 0 {
		return []string{"h2"}
	}

	out := make([]string, 0, len(alpn))
	seen := make(map[string]struct{}, len(alpn))
	for _, item := range alpn {
		token := strings.ToLower(strings.TrimSpace(item))
		switch token {
		case "h2", "h3", "http/1.1":
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			out = append(out, token)
		}
	}

	if len(out) == 0 {
		return []string{"h2"}
	}

	return out
}

func mergeXHTTPHeaders(base map[string]string, override map[string]string) map[string]string {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}

	headers := make(map[string]string, len(base)+len(override))
	for key, value := range base {
		headers[key] = value
	}
	for key, value := range override {
		headers[key] = value
	}
	return headers
}

func buildXHTTPConfig(network string, addr string, serverName string, alpn []string, primary XHTTPOptions, compat SplitHTTPOptions, hasReality bool) (*xhttp.Config, error) {
	option := selectXHTTPOptions(network, primary, compat)

	host, _, _ := net.SplitHostPort(addr)
	requestHost := option.Host
	if requestHost == "" {
		if serverName != "" {
			requestHost = serverName
		} else {
			requestHost = host
		}
	}

	cfg := &xhttp.Config{
		Host:          requestHost,
		Path:          option.Path,
		Mode:          option.Mode,
		Headers:       option.Headers,
		NoGRPCHeader:  option.NoGRPCHeader,
		XPaddingBytes: option.XPaddingBytes,
		ALPN:          normalizeXHTTPALPN(alpn),
		HasReality:    hasReality,
	}
	if option.TryQUIC == nil {
		cfg.TryQUIC = true
	} else {
		cfg.TryQUIC = *option.TryQUIC
	}

	if ds := option.DownloadSettings; ds != nil {
		realityCfg, err := ds.RealityOpts.Parse()
		if err != nil {
			return nil, err
		}

		cfg.DownloadSettings = &xhttp.DownloadConfig{
			Server:            ds.Server,
			Port:              ds.Port,
			TLS:               ds.TLS,
			Headers:           ds.Headers,
			Host:              ds.Host,
			Path:              ds.Path,
			Mode:              ds.Mode,
			ServerName:        ds.ServerName,
			ClientFingerprint: ds.ClientFingerprint,
			SkipCertVerify:    ds.SkipCertVerify,
			Reality:           realityCfg,
		}
	}

	return cfg, nil
}

func (o xhttpTLSOptions) normalizedServerName() string {
	if o.ServerName != "" {
		return o.ServerName
	}
	host, _, _ := net.SplitHostPort(o.Address)
	return host
}

func (o xhttpTLSOptions) wrapConn(ctx context.Context, conn net.Conn, forceH2 bool) (net.Conn, error) {
	if !o.TLSEnabled {
		return conn, nil
	}

	nextProtos := o.ALPN
	if forceH2 {
		nextProtos = []string{"h2"}
	}

	return mihomoVMess.StreamTLSConn(ctx, conn, &mihomoVMess.TLSConfig{
		Host:              o.normalizedServerName(),
		SkipCertVerify:    o.SkipCertVerify,
		FingerPrint:       o.Fingerprint,
		Certificate:       o.Certificate,
		PrivateKey:        o.PrivateKey,
		ClientFingerprint: o.ClientFingerprint,
		NextProtos:        nextProtos,
		ECH:               o.ECH,
		Reality:           o.Reality,
	})
}

func (o xhttpTLSOptions) standardTLSConfig(ctx context.Context, nextProtos []string) (*tls.Config, error) {
	if !o.TLSEnabled {
		return nil, fmt.Errorf("xhttp http/3 requires tls")
	}
	if o.Reality != nil {
		return nil, fmt.Errorf("xhttp http/3 does not support reality")
	}

	tlsConfig, err := (&mihomoVMess.TLSConfig{
		Host:           o.normalizedServerName(),
		SkipCertVerify: o.SkipCertVerify,
		FingerPrint:    o.Fingerprint,
		Certificate:    o.Certificate,
		PrivateKey:     o.PrivateKey,
		NextProtos:     nextProtos,
	}).ToStdConfig()
	if err != nil {
		return nil, err
	}
	if err := o.ECH.ClientHandle(ctx, tlsConfig); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

func (o xhttpTLSOptions) cloneForDownload(ds *xhttp.DownloadConfig) (xhttpTLSOptions, error) {
	if ds == nil {
		return o, nil
	}

	clone := o
	server, port, err := net.SplitHostPort(o.Address)
	if err != nil {
		return clone, err
	}

	if ds.Server != "" {
		server = ds.Server
	}
	if ds.Port != 0 {
		port = strconv.Itoa(ds.Port)
	}
	clone.Address = net.JoinHostPort(server, port)

	if ds.TLS != nil {
		clone.TLSEnabled = *ds.TLS
		clone.Reality = nil
	}
	if ds.Reality != nil {
		if ds.TLS != nil && !*ds.TLS {
			return clone, fmt.Errorf("xhttp download-settings reality-opts requires tls")
		}
		clone.TLSEnabled = true
		clone.Reality = ds.Reality
	}

	if ds.ServerName != "" {
		clone.ServerName = ds.ServerName
	}
	if ds.ClientFingerprint != "" {
		clone.ClientFingerprint = ds.ClientFingerprint
	}
	if ds.SkipCertVerify {
		clone.SkipCertVerify = true
	}

	return clone, nil
}

func buildHTTP2RoundTripperFactory(dialer C.Dialer, option xhttpTLSOptions) xhttp.RoundTripperFactory {
	return func(ctx context.Context) (http.RoundTripper, error) {
		return &http.Http2Transport{
			DialTLSContext: func(ctx context.Context, network string, addr string, _ *tls.Config) (net.Conn, error) {
				raw, err := dialer.DialContext(ctx, "tcp", option.Address)
				if err != nil {
					return nil, err
				}

				wrapped, err := option.wrapConn(ctx, raw, true)
				if err != nil {
					_ = raw.Close()
					return nil, err
				}

				return wrapped, nil
			},
		}, nil
	}
}

func buildHTTP3RoundTripperFactory(dialer C.Dialer, option xhttpTLSOptions) xhttp.RoundTripperFactory {
	return func(ctx context.Context) (http.RoundTripper, error) {
		tlsConfig, err := option.standardTLSConfig(ctx, []string{"h3"})
		if err != nil {
			return nil, err
		}

		return &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				KeepAlivePeriod: 15 * time.Second,
			},
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
				udpAddr, err := net.ResolveUDPAddr("udp", option.Address)
				if err != nil {
					return nil, err
				}

				packetConn, err := dialer.ListenPacket(ctx, "udp", "", udpAddr.AddrPort())
				if err != nil {
					return nil, err
				}

				quicConn, err := quic.DialEarly(ctx, packetConn, udpAddr, tlsCfg, quicCfg)
				if err != nil {
					_ = packetConn.Close()
					return nil, err
				}

				return quicConn, nil
			},
		}, nil
	}
}

func dialXHTTPConn(ctx context.Context, dialer C.Dialer, cfg *xhttp.Config, uploadTLS xhttpTLSOptions) (net.Conn, error) {
	downloadTLS, err := uploadTLS.cloneForDownload(cfg.DownloadSettings)
	if err != nil {
		return nil, err
	}

	mode := cfg.EffectiveMode()
	if mode == "stream-one" && cfg.DownloadSettings != nil {
		return nil, fmt.Errorf(`xhttp mode "stream-one" cannot be used with download-settings`)
	}

	if cfg.ShouldTryHTTP3() {
		uploadH3 := buildHTTP3RoundTripperFactory(dialer, uploadTLS)
		downloadH3 := buildHTTP3RoundTripperFactory(dialer, downloadTLS)

		switch mode {
		case "stream-one":
			conn, err := xhttp.DialStreamOne(ctx, cfg, uploadH3)
			if err == nil {
				return conn, nil
			}
			if !cfg.SupportsHTTP2() {
				return nil, err
			}
		case "stream-up":
			conn, err := xhttp.DialStreamUp(ctx, cfg, uploadH3, downloadH3)
			if err == nil {
				return conn, nil
			}
			if !cfg.SupportsHTTP2() {
				return nil, err
			}
		case "packet-up":
			conn, err := xhttp.DialPacketUp(ctx, cfg, uploadH3, downloadH3)
			if err == nil {
				return conn, nil
			}
			if !cfg.SupportsHTTP2() {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("xhttp mode %s is not implemented yet", mode)
		}
	}

	if !cfg.SupportsHTTP2() {
		return nil, fmt.Errorf("xhttp requires h2 or h3 transport, got alpn=%v", cfg.ALPN)
	}

	uploadH2 := buildHTTP2RoundTripperFactory(dialer, uploadTLS)
	downloadH2 := buildHTTP2RoundTripperFactory(dialer, downloadTLS)

	switch mode {
	case "stream-one":
		return xhttp.DialStreamOne(ctx, cfg, uploadH2)
	case "stream-up":
		return xhttp.DialStreamUp(ctx, cfg, uploadH2, downloadH2)
	case "packet-up":
		return xhttp.DialPacketUp(ctx, cfg, uploadH2, downloadH2)
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", mode)
	}
}
