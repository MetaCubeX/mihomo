package httpmask

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

const (
	tunnelEarlyDataQueryKey = "ed"
	tunnelEarlyDataHeader   = "X-Sudoku-Early"
)

type ClientEarlyHandshake struct {
	RequestPayload []byte
	HandleResponse func(payload []byte) error
	Ready          func() bool
	WrapConn       func(raw net.Conn) (net.Conn, error)
}

type TunnelServerEarlyHandshake struct {
	Prepare func(payload []byte) (*PreparedServerEarlyHandshake, error)
}

type PreparedServerEarlyHandshake struct {
	ResponsePayload []byte
	WrapConn        func(raw net.Conn) (net.Conn, error)
	UserHash        string
}

type earlyHandshakeMeta interface {
	HTTPMaskEarlyHandshakeUserHash() string
}

type earlyHandshakeConn struct {
	net.Conn
	userHash string
}

func (c *earlyHandshakeConn) HTTPMaskEarlyHandshakeUserHash() string {
	if c == nil {
		return ""
	}
	return c.userHash
}

func wrapEarlyHandshakeConn(conn net.Conn, userHash string) net.Conn {
	if conn == nil {
		return nil
	}
	return &earlyHandshakeConn{Conn: conn, userHash: userHash}
}

func EarlyHandshakeUserHash(conn net.Conn) (string, bool) {
	if conn == nil {
		return "", false
	}
	v, ok := conn.(earlyHandshakeMeta)
	if !ok {
		return "", false
	}
	return v.HTTPMaskEarlyHandshakeUserHash(), true
}

type authorizeResponse struct {
	token        string
	earlyPayload []byte
}

func isTunnelTokenByte(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' ||
		c == '_'
}

func parseAuthorizeResponse(body []byte) (*authorizeResponse, error) {
	s := strings.TrimSpace(string(body))
	idx := strings.Index(s, "token=")
	if idx < 0 {
		return nil, errors.New("missing token")
	}
	s = s[idx+len("token="):]
	if s == "" {
		return nil, errors.New("empty token")
	}

	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isTunnelTokenByte(c) {
			b.WriteByte(c)
			continue
		}
		break
	}
	token := b.String()
	if token == "" {
		return nil, errors.New("empty token")
	}

	out := &authorizeResponse{token: token}
	if earlyLine := findAuthorizeField(body, "ed="); earlyLine != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(earlyLine)
		if err != nil {
			return nil, fmt.Errorf("decode early authorize payload failed: %w", err)
		}
		out.earlyPayload = decoded
	}
	return out, nil
}

func findAuthorizeField(body []byte, prefix string) string {
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func setEarlyDataQuery(rawURL string, payload []byte) (string, error) {
	if len(payload) == 0 {
		return rawURL, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(tunnelEarlyDataQueryKey, base64.RawURLEncoding.EncodeToString(payload))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func parseEarlyDataQuery(u *url.URL) ([]byte, error) {
	if u == nil {
		return nil, nil
	}
	val := strings.TrimSpace(u.Query().Get(tunnelEarlyDataQueryKey))
	if val == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(val)
}

func applyEarlyHandshakeOrUpgrade(raw net.Conn, opts TunnelDialOptions) (net.Conn, error) {
	out := raw
	if opts.EarlyHandshake != nil && opts.EarlyHandshake.WrapConn != nil && (opts.EarlyHandshake.Ready == nil || opts.EarlyHandshake.Ready()) {
		wrapped, err := opts.EarlyHandshake.WrapConn(raw)
		if err != nil {
			return nil, err
		}
		if wrapped != nil {
			out = wrapped
		}
		return out, nil
	}
	if opts.Upgrade != nil {
		wrapped, err := opts.Upgrade(raw)
		if err != nil {
			return nil, err
		}
		if wrapped != nil {
			out = wrapped
		}
	}
	return out, nil
}
