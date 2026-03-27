package outbound

import (
	"context"
	"net"
	"strings"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/transport/splithttp"
)

type SplitHTTPOptions struct {
	Host                string            `proxy:"host,omitempty"`
	Path                string            `proxy:"path,omitempty"`
	Headers             map[string]string `proxy:"headers,omitempty"`
	MaxUploadSize       int               `proxy:"max-upload-size,omitempty"`
	MaxConcurrentPosts  int               `proxy:"max-concurrent-posts,omitempty"`
	Mode                string            `proxy:"mode,omitempty"`
	XPaddingBytesFrom   int               `proxy:"x-padding-bytes-from,omitempty"`
	XPaddingBytesTo     int               `proxy:"x-padding-bytes-to,omitempty"`
	XPaddingObfsMode    bool              `proxy:"x-padding-obfs-mode,omitempty"`
	XPaddingKey         string            `proxy:"x-padding-key,omitempty"`
	XPaddingHeader      string            `proxy:"x-padding-header,omitempty"`
	XPaddingPlacement   string            `proxy:"x-padding-placement,omitempty"`
	XPaddingMethod      string            `proxy:"x-padding-method,omitempty"`
	UplinkHTTPMethod    string            `proxy:"uplink-http-method,omitempty"`
	SessionPlacement    string            `proxy:"session-placement,omitempty"`
	SessionKey          string            `proxy:"session-key,omitempty"`
	SeqPlacement        string            `proxy:"seq-placement,omitempty"`
	SeqKey              string            `proxy:"seq-key,omitempty"`
	UplinkDataPlacement string            `proxy:"uplink-data-placement,omitempty"`
	UplinkDataKey       string            `proxy:"uplink-data-key,omitempty"`
	RequestLog          bool              `proxy:"request-log,omitempty"`
}

func normalizeSplitHTTPDialAddr(ctx context.Context, addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if net.ParseIP(host) != nil {
		return addr
	}
	ip, err := resolver.ResolveIP(ctx, host)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(ip.String(), port)
}

func decideXHTTPALPN(alpn []string) []string {
	if len(alpn) != 1 {
		return []string{"h2"}
	}
	p := strings.ToLower(alpn[0])
	if p == "h3" || p == "http/1.1" {
		return []string{p}
	}
	return []string{"h2"}
}

func buildSplitHTTPConfig(ctx context.Context, addr string, tlsServerName string, alpn []string, xhttpOpts SplitHTTPOptions, splitHTTPOpts SplitHTTPOptions, tlsEnabled bool) *splithttp.SplitHTTPConfig {
	host, _, _ := net.SplitHostPort(addr)
	config := &splithttp.SplitHTTPConfig{
		Host:                xhttpOpts.Host,
		Path:                xhttpOpts.Path,
		ALPN:                decideXHTTPALPN(alpn),
		DialAddr:            normalizeSplitHTTPDialAddr(ctx, addr),
		TLSServerName:       tlsServerName,
		Headers:             http.Header{},
		MaxUploadSize:       xhttpOpts.MaxUploadSize,
		MaxConcurrentPosts:  xhttpOpts.MaxConcurrentPosts,
		Mode:                xhttpOpts.Mode,
		TLS:                 tlsEnabled,
		XPaddingObfsMode:    xhttpOpts.XPaddingObfsMode,
		XPaddingKey:         xhttpOpts.XPaddingKey,
		XPaddingHeader:      xhttpOpts.XPaddingHeader,
		XPaddingPlacement:   xhttpOpts.XPaddingPlacement,
		XPaddingMethod:      xhttpOpts.XPaddingMethod,
		UplinkHTTPMethod:    xhttpOpts.UplinkHTTPMethod,
		SessionPlacement:    xhttpOpts.SessionPlacement,
		SessionKey:          xhttpOpts.SessionKey,
		SeqPlacement:        xhttpOpts.SeqPlacement,
		SeqKey:              xhttpOpts.SeqKey,
		UplinkDataPlacement: xhttpOpts.UplinkDataPlacement,
		UplinkDataKey:       xhttpOpts.UplinkDataKey,
		RequestLog:          xhttpOpts.RequestLog,
	}
	if xhttpOpts.XPaddingBytesTo > 0 {
		config.XPaddingBytes = &splithttp.RangeConfig{From: xhttpOpts.XPaddingBytesFrom, To: xhttpOpts.XPaddingBytesTo}
	}

	if config.Host == "" {
		config.Host = host
	}

	if splitHTTPOpts.Host != "" {
		config.Host = splitHTTPOpts.Host
	}
	if splitHTTPOpts.Path != "" {
		config.Path = splitHTTPOpts.Path
	}
	if splitHTTPOpts.MaxUploadSize > 0 {
		config.MaxUploadSize = splitHTTPOpts.MaxUploadSize
	}
	if splitHTTPOpts.MaxConcurrentPosts > 0 {
		config.MaxConcurrentPosts = splitHTTPOpts.MaxConcurrentPosts
	}
	if splitHTTPOpts.Mode != "" {
		config.Mode = splitHTTPOpts.Mode
	}
	if splitHTTPOpts.XPaddingBytesTo > 0 {
		config.XPaddingBytes = &splithttp.RangeConfig{From: splitHTTPOpts.XPaddingBytesFrom, To: splitHTTPOpts.XPaddingBytesTo}
	}
	if splitHTTPOpts.XPaddingObfsMode {
		config.XPaddingObfsMode = true
	}
	if splitHTTPOpts.XPaddingKey != "" {
		config.XPaddingKey = splitHTTPOpts.XPaddingKey
	}
	if splitHTTPOpts.XPaddingHeader != "" {
		config.XPaddingHeader = splitHTTPOpts.XPaddingHeader
	}
	if splitHTTPOpts.XPaddingPlacement != "" {
		config.XPaddingPlacement = splitHTTPOpts.XPaddingPlacement
	}
	if splitHTTPOpts.XPaddingMethod != "" {
		config.XPaddingMethod = splitHTTPOpts.XPaddingMethod
	}
	if splitHTTPOpts.UplinkHTTPMethod != "" {
		config.UplinkHTTPMethod = splitHTTPOpts.UplinkHTTPMethod
	}
	if splitHTTPOpts.SessionPlacement != "" {
		config.SessionPlacement = splitHTTPOpts.SessionPlacement
	}
	if splitHTTPOpts.SessionKey != "" {
		config.SessionKey = splitHTTPOpts.SessionKey
	}
	if splitHTTPOpts.SeqPlacement != "" {
		config.SeqPlacement = splitHTTPOpts.SeqPlacement
	}
	if splitHTTPOpts.SeqKey != "" {
		config.SeqKey = splitHTTPOpts.SeqKey
	}
	if splitHTTPOpts.UplinkDataPlacement != "" {
		config.UplinkDataPlacement = splitHTTPOpts.UplinkDataPlacement
	}
	if splitHTTPOpts.UplinkDataKey != "" {
		config.UplinkDataKey = splitHTTPOpts.UplinkDataKey
	}
	if splitHTTPOpts.RequestLog {
		config.RequestLog = true
	}

	for k, v := range xhttpOpts.Headers {
		config.Headers.Set(k, v)
	}
	for k, v := range splitHTTPOpts.Headers {
		config.Headers.Set(k, v)
	}

	return config
}
