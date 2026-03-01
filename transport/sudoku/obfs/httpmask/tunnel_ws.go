package httpmask

import (
	"context"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	stdhttp "net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gobwas/ws"
	"github.com/metacubex/tls"
)

func normalizeWSSchemeFromAddress(serverAddress string, tlsEnabled bool) (string, string) {
	addr := strings.TrimSpace(serverAddress)
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil && u != nil {
			switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
			case "ws":
				return "ws", u.Host
			case "wss":
				return "wss", u.Host
			}
		}
	}
	if tlsEnabled {
		return "wss", addr
	}
	return "ws", addr
}

func normalizeWSDialTarget(serverAddress string, tlsEnabled bool, hostOverride string) (scheme, urlHost, dialAddr, serverName string, err error) {
	scheme, addr := normalizeWSSchemeFromAddress(serverAddress, tlsEnabled)

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Allow ws(s)://host without port.
		if strings.Contains(addr, ":") {
			return "", "", "", "", fmt.Errorf("invalid server address %q: %w", serverAddress, err)
		}
		switch scheme {
		case "wss":
			port = "443"
		default:
			port = "80"
		}
		host = addr
	}

	if hostOverride != "" {
		// Allow "example.com" or "example.com:443"
		if h, p, splitErr := net.SplitHostPort(hostOverride); splitErr == nil {
			if h != "" {
				hostOverride = h
			}
			if p != "" {
				port = p
			}
		}
		serverName = hostOverride
		urlHost = net.JoinHostPort(hostOverride, port)
	} else {
		serverName = host
		urlHost = net.JoinHostPort(host, port)
	}

	dialAddr = net.JoinHostPort(host, port)
	return scheme, urlHost, dialAddr, trimPortForHost(serverName), nil
}

func applyWSHeaders(h stdhttp.Header, host string) {
	if h == nil {
		return
	}
	r := rngPool.Get().(*mrand.Rand)
	ua := userAgents[r.Intn(len(userAgents))]
	accept := accepts[r.Intn(len(accepts))]
	lang := acceptLanguages[r.Intn(len(acceptLanguages))]
	enc := acceptEncodings[r.Intn(len(acceptEncodings))]
	rngPool.Put(r)

	h.Set("User-Agent", ua)
	h.Set("Accept", accept)
	h.Set("Accept-Language", lang)
	h.Set("Accept-Encoding", enc)
	h.Set("Cache-Control", "no-cache")
	h.Set("Pragma", "no-cache")
	h.Set("X-Sudoku-Tunnel", string(TunnelModeWS))
	h.Set("X-Sudoku-Version", "1")
}

func dialWS(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	if opts.DialContext == nil {
		panic("httpmask: DialContext is nil")
	}

	scheme, urlHost, dialAddr, serverName, err := normalizeWSDialTarget(serverAddress, opts.TLSEnabled, opts.HostOverride)
	if err != nil {
		return nil, err
	}

	httpScheme := "http"
	if scheme == "wss" {
		httpScheme = "https"
	}
	headerHost := canonicalHeaderHost(urlHost, httpScheme)
	auth := newTunnelAuth(opts.AuthKey, 0)

	u := &url.URL{
		Scheme: scheme,
		Host:   urlHost,
		Path:   joinPathRoot(opts.PathRoot, "/ws"),
	}

	header := make(stdhttp.Header)
	applyWSHeaders(header, headerHost)

	if auth != nil {
		token := auth.token(TunnelModeWS, stdhttp.MethodGet, "/ws", time.Now())
		if token != "" {
			header.Set("Authorization", "Bearer "+token)
			q := u.Query()
			q.Set(tunnelAuthQueryKey, token)
			u.RawQuery = q.Encode()
		}
	}

	d := ws.Dialer{
		Host:   headerHost,
		Header: ws.HandshakeHeaderHTTP(header),
		NetDial: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			if addr == urlHost {
				addr = dialAddr
			}
			return opts.DialContext(dialCtx, network, addr)
		},
	}
	if scheme == "wss" {
		tlsConfig := &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}
		d.TLSClient = func(conn net.Conn, hostname string) net.Conn {
			return tls.Client(conn, tlsConfig)
		}
	}

	conn, br, _, err := d.Dial(ctx, u.String())
	if err != nil {
		return nil, err
	}

	if br != nil && br.Buffered() > 0 {
		pre := make([]byte, br.Buffered())
		_, _ = io.ReadFull(br, pre)
		conn = newPreBufferedConn(conn, pre)
	}

	wsConn := newWSStreamConn(conn, ws.StateClientSide)
	if opts.Upgrade == nil {
		return wsConn, nil
	}
	upgraded, err := opts.Upgrade(wsConn)
	if err != nil {
		_ = wsConn.Close()
		return nil, err
	}
	if upgraded != nil {
		return upgraded, nil
	}
	return wsConn, nil
}
