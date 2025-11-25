package inbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/xhttp"
	utls "github.com/metacubex/utls"
)

type XhttpOption struct {
	BaseOption
	Host                 string            `inbound:"host,omitempty"`
	Path                 string            `inbound:"path,omitempty"`
	Mode                 string            `inbound:"mode,omitempty"`
	HTTPVersion          string            `inbound:"http-version,omitempty"`
	Headers              map[string]string `inbound:"headers,omitempty"`
	NoGRPCHeader         bool              `inbound:"no-grpc-header,omitempty"`
	NoSSEHeader          bool              `inbound:"no-sse-header,omitempty"`
	XPaddingBytes        string            `inbound:"x-padding-bytes,omitempty"`
	ScMaxEachPostBytes   string            `inbound:"sc-max-each-post-bytes,omitempty"`
	ScMinPostsIntervalMs string            `inbound:"sc-min-posts-interval-ms,omitempty"`
	ScMaxBufferedPosts   string            `inbound:"sc-max-buffered-posts,omitempty"`
	ScStreamUpServerSecs string            `inbound:"sc-stream-up-server-secs,omitempty"`
	DownloadSettings     *XhttpOption      `inbound:"download-settings,omitempty"`
	Xmux                 XhttpXmuxOption   `inbound:"xmux,omitempty"`
	Certificate          string            `inbound:"certificate,omitempty"`
	PrivateKey           string            `inbound:"private-key,omitempty"`
}

type XhttpXmuxOption struct {
	MaxConcurrency   string `inbound:"max-concurrency,omitempty"`
	MaxConnections   string `inbound:"max-connections,omitempty"`
	CMaxReuseTimes   string `inbound:"c-max-reuse-times,omitempty"`
	HMaxRequestTimes string `inbound:"h-max-request-times,omitempty"`
	HMaxReusableSecs string `inbound:"h-max-reusable-secs,omitempty"`
	HKeepAlivePeriod int64  `inbound:"h-keep-alive-period,omitempty"`
}

// parseRangeConfig parses a string into xhttp.Range with proper error handling
func parseRangeConfig(value, fieldName string) xhttp.Range {
	var r xhttp.Range
	if value != "" {
		if err := r.UnmarshalText([]byte(value)); err != nil {
			log.Warnln("xhttp: invalid %s %q: %v", fieldName, value, err)
		}
	}
	return r
}

// parseXmuxRanges parses all xmux range options
func parseXmuxRanges(xmux XhttpXmuxOption) (maxConcurrency, maxConnections, cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs xhttp.Range) {
	maxConcurrency = parseRangeConfig(xmux.MaxConcurrency, "max-concurrency")
	maxConnections = parseRangeConfig(xmux.MaxConnections, "max-connections")
	cMaxReuseTimes = parseRangeConfig(xmux.CMaxReuseTimes, "c-max-reuse-times")
	hMaxRequestTimes = parseRangeConfig(xmux.HMaxRequestTimes, "h-max-request-times")
	hMaxReusableSecs = parseRangeConfig(xmux.HMaxReusableSecs, "h-max-reusable-secs")
	return
}

func (o XhttpOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Xhttp struct {
	*Base
	config   *XhttpOption
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	xs       LC.XhttpServer
}

func NewXhttp(options *XhttpOption) (*Xhttp, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}

	var xPaddingBytes, scMaxEachPostBytes, scMinPostsIntervalMs, scMaxBufferedPosts, scStreamUpServerSecs xhttp.Range
	xPaddingBytes = parseRangeConfig(options.XPaddingBytes, "x-padding-bytes")
	scMaxEachPostBytes = parseRangeConfig(options.ScMaxEachPostBytes, "sc-max-each-post-bytes")
	scMinPostsIntervalMs = parseRangeConfig(options.ScMinPostsIntervalMs, "sc-min-posts-interval-ms")
	scMaxBufferedPosts = parseRangeConfig(options.ScMaxBufferedPosts, "sc-max-buffered-posts")
	scStreamUpServerSecs = parseRangeConfig(options.ScStreamUpServerSecs, "sc-stream-up-server-secs")

	xmuxMaxConcurrency, xmuxMaxConnections, xmuxCMaxReuseTimes, xmuxHMaxRequestTimes, xmuxHMaxReusableSecs := parseXmuxRanges(options.Xmux)

	return &Xhttp{
		Base:   base,
		config: options,
		xs: LC.XhttpServer{
			Enable:               true,
			Listen:               base.RawAddress(),
			Host:                 options.Host,
			Path:                 options.Path,
			Mode:                 options.Mode,
			HTTPVersion:          options.HTTPVersion,
			Headers:              options.Headers,
			NoGRPCHeader:         options.NoGRPCHeader,
			NoSSEHeader:          options.NoSSEHeader,
			XPaddingBytes:        xPaddingBytes,
			ScMaxEachPostBytes:   scMaxEachPostBytes,
			ScMinPostsIntervalMs: scMinPostsIntervalMs,
			ScMaxBufferedPosts:   scMaxBufferedPosts,
			ScStreamUpServerSecs: scStreamUpServerSecs,
			DownloadSettings:     parseDownloadSettings(options.DownloadSettings),
			Xmux: LC.XhttpXmuxConfig{
				MaxConcurrency:   xmuxMaxConcurrency,
				MaxConnections:   xmuxMaxConnections,
				CMaxReuseTimes:   xmuxCMaxReuseTimes,
				HMaxRequestTimes: xmuxHMaxRequestTimes,
				HMaxReusableSecs: xmuxHMaxReusableSecs,
				HKeepAlivePeriod: options.Xmux.HKeepAlivePeriod,
			},
			Certificate: options.Certificate,
			PrivateKey:  options.PrivateKey,
		},
	}, nil
}

func convertDownloadSettings(downloadServer *LC.XhttpServer) *xhttp.Config {
	if downloadServer == nil {
		return nil
	}

	return &xhttp.Config{
		Host:                 downloadServer.Host,
		Path:                 downloadServer.Path,
		Mode:                 downloadServer.Mode,
		Headers:              downloadServer.Headers,
		NoGRPCHeader:         downloadServer.NoGRPCHeader,
		NoSSEHeader:          downloadServer.NoSSEHeader,
		HTTPVersion:          downloadServer.HTTPVersion,
		XPaddingBytes:        downloadServer.XPaddingBytes,
		ScMaxEachPostBytes:   downloadServer.ScMaxEachPostBytes,
		ScMinPostsIntervalMs: downloadServer.ScMinPostsIntervalMs,
		ScMaxBufferedPosts:   downloadServer.ScMaxBufferedPosts,
		ScStreamUpServerSecs: downloadServer.ScStreamUpServerSecs,
		Download:             nil,
		Xmux: &xhttp.XmuxConfig{
			MaxConcurrency:   downloadServer.Xmux.MaxConcurrency,
			MaxConnections:   downloadServer.Xmux.MaxConnections,
			CMaxReuseTimes:   downloadServer.Xmux.CMaxReuseTimes,
			HMaxRequestTimes: downloadServer.Xmux.HMaxRequestTimes,
			HMaxReusableSecs: downloadServer.Xmux.HMaxReusableSecs,
			HKeepAlivePeriod: downloadServer.Xmux.HKeepAlivePeriod,
		},
	}
}

func parseDownloadSettings(downloadOpt *XhttpOption) *LC.XhttpServer {
	if downloadOpt == nil {
		return nil
	}

	var xPaddingBytes, scMaxEachPostBytes, scMinPostsIntervalMs, scMaxBufferedPosts, scStreamUpServerSecs xhttp.Range
	xPaddingBytes = parseRangeConfig(downloadOpt.XPaddingBytes, "x-padding-bytes")
	scMaxEachPostBytes = parseRangeConfig(downloadOpt.ScMaxEachPostBytes, "sc-max-each-post-bytes")
	scMinPostsIntervalMs = parseRangeConfig(downloadOpt.ScMinPostsIntervalMs, "sc-min-posts-interval-ms")
	scMaxBufferedPosts = parseRangeConfig(downloadOpt.ScMaxBufferedPosts, "sc-max-buffered-posts")
	scStreamUpServerSecs = parseRangeConfig(downloadOpt.ScStreamUpServerSecs, "sc-stream-up-server-secs")

	xmuxMaxConcurrency, xmuxMaxConnections, xmuxCMaxReuseTimes, xmuxHMaxRequestTimes, xmuxHMaxReusableSecs := parseXmuxRanges(downloadOpt.Xmux)

	return &LC.XhttpServer{
		Enable:               false,
		Listen:               "",
		Host:                 downloadOpt.Host,
		Path:                 downloadOpt.Path,
		Mode:                 downloadOpt.Mode,
		HTTPVersion:          downloadOpt.HTTPVersion,
		Headers:              downloadOpt.Headers,
		NoGRPCHeader:         downloadOpt.NoGRPCHeader,
		NoSSEHeader:          downloadOpt.NoSSEHeader,
		XPaddingBytes:        xPaddingBytes,
		ScMaxEachPostBytes:   scMaxEachPostBytes,
		ScMinPostsIntervalMs: scMinPostsIntervalMs,
		ScMaxBufferedPosts:   scMaxBufferedPosts,
		ScStreamUpServerSecs: scStreamUpServerSecs,
		DownloadSettings:     nil,
		Xmux: LC.XhttpXmuxConfig{
			MaxConcurrency:   xmuxMaxConcurrency,
			MaxConnections:   xmuxMaxConnections,
			CMaxReuseTimes:   xmuxCMaxReuseTimes,
			HMaxRequestTimes: xmuxHMaxRequestTimes,
			HMaxReusableSecs: xmuxHMaxReusableSecs,
			HKeepAlivePeriod: downloadOpt.Xmux.HKeepAlivePeriod,
		},
		Certificate: downloadOpt.Certificate,
		PrivateKey:  downloadOpt.PrivateKey,
	}
}

func loadTLSConfig(certFile, keyFile, httpVersion string) (any, error) {
	version := httpVersion
	if version == "" || version == "auto" {
		version = "2"
	}

	if version == "3" || version == "h3" {
		cert, err := utls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load X509 key pair for HTTP/3: %w", err)
		}
		return &utls.Config{
			Certificates: []utls.Certificate{cert},
			MinVersion:   utls.VersionTLS13,
			NextProtos:   []string{"h3"},
		}, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if version == "2" || version == "h2" {
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	} else {
		tlsCfg.NextProtos = []string{"http/1.1"}
	}

	return tlsCfg, nil
}

func (x *Xhttp) Config() C.InboundConfig {
	return x.config
}

func (x *Xhttp) Address() string {
	if x.listener != nil {
		return x.listener.Addr().String()
	}
	return x.RawAddress()
}

func (x *Xhttp) Listen(tunnel C.Tunnel) error {
	var err error

	xhttpConfig := &xhttp.Config{
		Host:                 x.xs.Host,
		Path:                 x.xs.Path,
		Mode:                 x.xs.Mode,
		Headers:              x.xs.Headers,
		NoGRPCHeader:         x.xs.NoGRPCHeader,
		NoSSEHeader:          x.xs.NoSSEHeader,
		HTTPVersion:          x.xs.HTTPVersion,
		XPaddingBytes:        x.xs.XPaddingBytes,
		ScMaxEachPostBytes:   x.xs.ScMaxEachPostBytes,
		ScMinPostsIntervalMs: x.xs.ScMinPostsIntervalMs,
		ScMaxBufferedPosts:   x.xs.ScMaxBufferedPosts,
		ScStreamUpServerSecs: x.xs.ScStreamUpServerSecs,
		Download:             convertDownloadSettings(x.xs.DownloadSettings),
		Xmux: &xhttp.XmuxConfig{
			MaxConcurrency:   x.xs.Xmux.MaxConcurrency,
			MaxConnections:   x.xs.Xmux.MaxConnections,
			CMaxReuseTimes:   x.xs.Xmux.CMaxReuseTimes,
			HMaxRequestTimes: x.xs.Xmux.HMaxRequestTimes,
			HMaxReusableSecs: x.xs.Xmux.HMaxReusableSecs,
			HKeepAlivePeriod: x.xs.Xmux.HKeepAlivePeriod,
		},
	}

	addr := x.RawAddress()
	x.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("xhttp: failed to listen on %s: %w", addr, err)
	}

	var tlsConfig any
	if x.xs.Certificate != "" && x.xs.PrivateKey != "" {
		tlsConfig, err = loadTLSConfig(x.xs.Certificate, x.xs.PrivateKey, xhttpConfig.HTTPVersion)
		if err != nil {
			x.listener.Close()
			return fmt.Errorf("xhttp: failed to load TLS configuration: %w", err)
		}
		log.Infoln("XHTTP TLS loaded: cert=%s, http-version=%s", x.xs.Certificate, xhttpConfig.HTTPVersion)
	}

	x.ctx, x.cancel = context.WithCancel(context.Background())

	err = xhttp.NewServer(x.ctx, xhttpConfig, tunnel, x.Additions(), x.listener, tlsConfig)
	if err != nil {
		x.listener.Close()
		return fmt.Errorf("xhttp: failed to start server: %w", err)
	}

	log.Infoln("XHTTP server listening on %s (mode: %s, http: %s)", addr, xhttpConfig.Mode, xhttpConfig.HTTPVersion)
	return nil
}

func (x *Xhttp) Close() error {
	if x.cancel != nil {
		x.cancel()
	}
	if x.listener != nil {
		return x.listener.Close()
	}
	return nil
}

var _ C.InboundListener = (*Xhttp)(nil)
