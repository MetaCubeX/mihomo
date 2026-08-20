// Package masque implements the client side of CONNECT-IP as specified by
// RFC 9484. Product-specific extensions belong in their respective packages.
package masque

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	connectip "github.com/metacubex/connect-ip-go"
	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/dunglas/httpsfv"
)

const (
	// RequestProtocol is the Extended CONNECT protocol registered by RFC 9484.
	RequestProtocol = "connect-ip"
	// DefaultPath is the well-known full-tunnel path from RFC 9484.
	DefaultPath = "/.well-known/masque/ip/*/*/"
	// CapsuleProtocolHeaderValue is the Structured Fields boolean true value
	// required by RFC 9297.
	CapsuleProtocolHeaderValue = "?1"
)

type IpConn interface {
	ReadPacket() (b []byte, err error)
	WritePacket(b []byte) (icmp []byte, err error)
	Close() error
}

// ParseTunnelURL parses and expands a CONNECT-IP URI template for a full
// tunnel. RFC 9484 defines target and ipproto semantics; this client fills
// both with the wildcard value and requires any deployment-specific variables
// to be expanded by the configuration author.
func ParseTunnelURL(raw string) (*url.URL, error) {
	if err := validateTemplateSyntax(raw); err != nil {
		return nil, err
	}
	template, err := uritemplate.New(raw)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: parse URI template: %w", err)
	}
	values := uritemplate.Values{}
	for _, name := range template.Varnames() {
		switch name {
		case "target", "ipproto":
			values.Set(name, uritemplate.String("*"))
		default:
			return nil, fmt.Errorf("connect-ip: unsupported URI template variable %q", name)
		}
	}
	expanded, err := template.Expand(values)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: expand URI template: %w", err)
	}
	u, err := url.Parse(expanded)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: parse expanded URI: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("connect-ip: URI scheme must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("connect-ip: URI is missing an authority")
	}
	if u.Path == "" || u.Path[0] != '/' {
		return nil, errors.New("connect-ip: URI path must be non-empty and start with a slash")
	}
	if u.User != nil {
		return nil, errors.New("connect-ip: URI authority must not contain userinfo")
	}
	if u.Fragment != "" {
		return nil, errors.New("connect-ip: URI must not contain a fragment")
	}
	return u, nil
}

func validateTemplateSyntax(raw string) error {
	for index := 0; index < len(raw); index++ {
		if raw[index] < 0x21 || raw[index] > 0x7e {
			return fmt.Errorf("connect-ip: URI template contains a non-ASCII or whitespace byte at offset %d", index)
		}
	}
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd <= 0 {
		return errors.New("connect-ip: URI template must be absolute")
	}
	authorityStart := schemeEnd + 3
	pathOffset := strings.IndexByte(raw[authorityStart:], '/')
	if pathOffset < 0 {
		return errors.New("connect-ip: URI template must contain a non-empty path")
	}
	pathStart := authorityStart + pathOffset
	fragmentStart := strings.IndexByte(raw, '#')
	if fragmentStart >= 0 {
		return errors.New("connect-ip: URI template must not contain a fragment")
	}
	for offset := 0; ; {
		startOffset := strings.IndexByte(raw[offset:], '{')
		if startOffset < 0 {
			break
		}
		start := offset + startOffset
		endOffset := strings.IndexByte(raw[start+1:], '}')
		if endOffset < 0 {
			break // uritemplate.New reports the more precise syntax error.
		}
		end := start + 1 + endOffset
		if start < pathStart {
			return errors.New("connect-ip: URI template variables must be in the path or query")
		}
		expression := raw[start+1 : end]
		if expression != "" && strings.ContainsRune("+#./;", rune(expression[0])) {
			return fmt.Errorf("connect-ip: URI template operator %q is not allowed by RFC 9484", expression[:1])
		}
		if strings.Contains(expression, ":") || strings.HasSuffix(expression, "*") || strings.Contains(expression, "*,") {
			return errors.New("connect-ip: URI template must be level 3 or lower")
		}
		offset = end + 1
	}
	return nil
}

// ConnectTunnel establishes a standards-compliant CONNECT-IP tunnel over
// HTTP/3. It requires both Extended CONNECT and HTTP Datagrams to have been
// enabled by the peer.
func ConnectTunnel(ctx context.Context, quicConn *quic.Conn, connectURI string, additionalHeaders http.Header) (*http3.Transport, *connectip.Conn, error) {
	u, err := ParseTunnelURL(connectURI)
	if err != nil {
		return nil, nil, err
	}

	tr := &http3.Transport{
		EnableDatagrams:    true,
		DisableCompression: true,
	}
	hconn := tr.NewClientConn(quicConn)
	ipConn, rsp, err := dialHTTP3(ctx, hconn, u, additionalHeaders)
	if err != nil {
		_ = tr.Close()
		return nil, nil, err
	}
	if err := validateCapsuleProtocol(rsp.Header); err != nil {
		_ = ipConn.Close()
		_ = tr.Close()
		return nil, nil, err
	}
	return tr, ipConn, nil
}

func dialHTTP3(ctx context.Context, conn *http3.ClientConn, u *url.URL, additionalHeaders http.Header) (*connectip.Conn, *http.Response, error) {
	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case <-conn.Context().Done():
		return nil, nil, context.Cause(conn.Context())
	case <-conn.ReceivedSettings():
	}
	settings := conn.Settings()
	if !settings.EnableExtendedConnect {
		return nil, nil, errors.New("connect-ip: server didn't enable Extended CONNECT")
	}
	if !settings.EnableDatagrams {
		return nil, nil, errors.New("connect-ip: server didn't enable HTTP Datagrams")
	}

	headers, err := requestHeaders(additionalHeaders)
	if err != nil {
		return nil, nil, err
	}
	rstr, err := conn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: open HTTP/3 request stream: %w", err)
	}
	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  RequestProtocol,
		Host:   u.Host,
		Header: headers,
		URL:    u,
	}); err != nil {
		_ = rstr.Close()
		return nil, nil, fmt.Errorf("connect-ip: send HTTP/3 request: %w", err)
	}
	rsp, err := rstr.ReadResponse()
	if err != nil {
		_ = rstr.Close()
		return nil, nil, fmt.Errorf("connect-ip: read HTTP/3 response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		_ = rstr.Close()
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %s", rsp.Status)
	}
	return connectip.NewProxiedConn(rstr), rsp, nil
}

func requestHeaders(additional http.Header) (http.Header, error) {
	headers := additional.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	for name := range headers {
		if len(name) > 0 && name[0] == ':' {
			return nil, fmt.Errorf("connect-ip: pseudo-header %q cannot be configured", name)
		}
	}
	headers.Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
	return headers, nil
}

func validateCapsuleProtocol(headers http.Header) error {
	values := headers.Values(http3.CapsuleProtocolHeader)
	if len(values) == 0 {
		return errors.New("connect-ip: successful response is missing Capsule-Protocol")
	}
	item, err := httpsfv.UnmarshalItem(values)
	if err != nil {
		return fmt.Errorf("connect-ip: invalid Capsule-Protocol response: %w", err)
	}
	value, ok := item.Value.(bool)
	if !ok {
		return fmt.Errorf("connect-ip: Capsule-Protocol response has type %s, want boolean", reflect.TypeOf(item.Value))
	}
	if !value {
		return errors.New("connect-ip: server declined the Capsule Protocol")
	}
	return nil
}
