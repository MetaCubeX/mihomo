package outbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type Http struct {
	*Base
	user      string
	pass      string
	tlsConfig *tls.Config
	option    *HttpOption
}

type HttpOption struct {
	BasicOption
	Name           string            `proxy:"name"`
	Server         string            `proxy:"server"`
	Port           int               `proxy:"port"`
	UserName       string            `proxy:"username,omitempty"`
	Password       string            `proxy:"password,omitempty"`
	TLS            bool              `proxy:"tls,omitempty"`
	SNI            string            `proxy:"sni,omitempty"`
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify string            `proxy:"name-cert-verify,omitempty"`
	Fingerprint    string            `proxy:"fingerprint,omitempty"`
	Certificate    string            `proxy:"certificate,omitempty"`
	PrivateKey     string            `proxy:"private-key,omitempty"`
	Headers        map[string]string `proxy:"headers,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (h *Http) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if h.tlsConfig != nil {
		started := time.Now()
		remaining := httpProxyRemaining(ctx)
		cc := tls.Client(c, h.tlsConfig)
		err := cc.HandshakeContext(ctx)
		c = cc
		if err != nil {
			return nil, h.diagnosticError("proxy-tls", c, started, remaining, err)
		}
	}

	started := time.Now()
	remaining := httpProxyRemaining(ctx)
	if err := h.shakeHandContext(ctx, c, metadata); err != nil {
		return nil, h.diagnosticError("http-connect", c, started, remaining, err)
	}
	return c, nil
}

// DialContext implements C.ProxyAdapter
func (h *Http) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	started := time.Now()
	remaining := httpProxyRemaining(ctx)
	c, err := h.dialer.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return nil, h.diagnosticError("proxy-dial", nil, started, remaining, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = h.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, h), nil
}

// proxy-dial includes address resolution and any configured upstream dialer.
// Wrapping CONNECT errors here keeps stage information after context cancellation.
func (h *Http) diagnosticError(stage string, conn net.Conn, started time.Time, remaining string, err error) error {
	peer := "unavailable"
	if conn != nil && conn.RemoteAddr() != nil {
		peer = conn.RemoteAddr().String()
	}
	return fmt.Errorf("stage=%s proxy=%s peer=%s stage_elapsed=%s remaining_at_start=%s: %w",
		stage, h.addr, peer, time.Since(started).Round(time.Millisecond), remaining, err)
}

func httpProxyRemaining(ctx context.Context) string {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < 0 {
			remaining = 0
		}
		return remaining.Round(time.Millisecond).String()
	}
	return "none"
}

// ReadResponse errors may quote untrusted response headers or status lines.
// Preserve their identity without copying response contents into log messages.
type httpProxyResponseError struct {
	cause error
}

func (e *httpProxyResponseError) Error() string { return "HTTP CONNECT response read/parse failed" }
func (e *httpProxyResponseError) Unwrap() error { return e.cause }

// ProxyInfo implements C.ProxyAdapter
func (h *Http) ProxyInfo() C.ProxyInfo {
	info := h.Base.ProxyInfo()
	info.DialerProxy = h.option.DialerProxy
	return info
}

func (h *Http) shakeHandContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	addr := metadata.RemoteAddress()
	HeaderString := "CONNECT " + addr + " HTTP/1.1\r\n"
	tempHeaders := map[string]string{
		"Host":             addr,
		"User-Agent":       "Go-http-client/1.1",
		"Proxy-Connection": "Keep-Alive",
	}

	for key, value := range h.option.Headers {
		tempHeaders[key] = value
	}

	if h.user != "" && h.pass != "" {
		auth := h.user + ":" + h.pass
		tempHeaders["Proxy-Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	}

	for key, value := range tempHeaders {
		HeaderString += key + ": " + value + "\r\n"
	}

	HeaderString += "\r\n"

	_, err = c.Write([]byte(HeaderString))

	if err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)

	if err != nil {
		return &httpProxyResponseError{cause: err}
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusProxyAuthRequired {
		return fmt.Errorf("HTTP need auth (status=%d %s)", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		return fmt.Errorf("CONNECT method not allowed by proxy (status=%d %s)", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("HTTP CONNECT rejected (status=%d %s)", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return fmt.Errorf("can not connect remote err code: %d", resp.StatusCode)
}

func NewHttp(option HttpOption) (*Http, error) {
	var tlsConfig *tls.Config
	if option.TLS {
		sni := option.Server
		if option.SNI != "" {
			sni = option.SNI
		}
		var err error
		tlsConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: option.SkipCertVerify,
				ServerName:         sni,
			},
			Fingerprint:    option.Fingerprint,
			NameCertVerify: option.NameCertVerify,
			Certificate:    option.Certificate,
			PrivateKey:     option.PrivateKey,
		})
		if err != nil {
			return nil, err
		}
	}

	outbound := &Http{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.Http,
			ProviderName: option.ProviderName,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		user:      option.UserName,
		pass:      option.Password,
		tlsConfig: tlsConfig,
		option:    &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
