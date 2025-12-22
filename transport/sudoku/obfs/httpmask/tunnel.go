package httpmask

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TunnelMode string

const (
	TunnelModeLegacy TunnelMode = "legacy"
	TunnelModeXHTTP  TunnelMode = "xhttp"
	TunnelModePHT    TunnelMode = "pht"
	TunnelModeAuto   TunnelMode = "auto"
)

func normalizeTunnelMode(mode string) TunnelMode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", string(TunnelModeLegacy):
		return TunnelModeLegacy
	case string(TunnelModeXHTTP):
		return TunnelModeXHTTP
	case string(TunnelModePHT):
		return TunnelModePHT
	case string(TunnelModeAuto):
		return TunnelModeAuto
	default:
		// Be conservative: unknown => legacy
		return TunnelModeLegacy
	}
}

type HandleResult int

const (
	HandlePassThrough HandleResult = iota
	HandleStartTunnel
	HandleDone
)

type TunnelDialOptions struct {
	Mode         string
	TLSEnabled   bool   // if false, scheme is auto-inferred from port (443 => https)
	HostOverride string // optional Host header / SNI host (without scheme); port inferred from ServerAddress
	// DialContext optionally overrides how the HTTP tunnel dials raw TCP/TLS connections.
	// When nil, a default net.Dialer is used.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// DialTunnel establishes a bidirectional stream over HTTP:
//   - xhttp: a single streaming POST (request body uplink, response body downlink)
//   - pht: authorize + push/pull polling tunnel (base64 framed)
//   - auto: try xhttp then fall back to pht
//
// The returned net.Conn carries the raw Sudoku stream (no HTTP headers).
func DialTunnel(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	mode := normalizeTunnelMode(opts.Mode)
	if mode == TunnelModeLegacy {
		return nil, fmt.Errorf("legacy mode does not use http tunnel")
	}

	switch mode {
	case TunnelModeXHTTP:
		return dialXHTTPFn(ctx, serverAddress, opts)
	case TunnelModePHT:
		return dialPHTFn(ctx, serverAddress, opts)
	case TunnelModeAuto:
		// "xhttp" can hang on some CDNs that buffer uploads until request body completes.
		// Keep it on a short leash so we can fall back to PHT within the caller's deadline.
		xhttpCtx, cancelX := context.WithTimeout(ctx, 3*time.Second)
		c, errX := dialXHTTPFn(xhttpCtx, serverAddress, opts)
		cancelX()
		if errX == nil {
			return c, nil
		}
		c, errP := dialPHTFn(ctx, serverAddress, opts)
		if errP == nil {
			return c, nil
		}
		return nil, fmt.Errorf("auto tunnel failed: xhttp: %v; pht: %w", errX, errP)
	default:
		return dialXHTTPFn(ctx, serverAddress, opts)
	}
}

var (
	dialXHTTPFn = dialXHTTP
	dialPHTFn   = dialPHT
)

func canonicalHeaderHost(urlHost, scheme string) string {
	host, port, err := net.SplitHostPort(urlHost)
	if err != nil {
		return urlHost
	}

	defaultPort := ""
	switch scheme {
	case "https":
		defaultPort = "443"
	case "http":
		defaultPort = "80"
	}
	if defaultPort == "" || port != defaultPort {
		return urlHost
	}

	// If we strip the port from an IPv6 literal, re-add brackets to keep the Host header valid.
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func parseTunnelToken(body []byte) (string, error) {
	s := strings.TrimSpace(string(body))
	idx := strings.Index(s, "token=")
	if idx < 0 {
		return "", errors.New("missing token")
	}
	s = s[idx+len("token="):]
	if s == "" {
		return "", errors.New("empty token")
	}
	// Token is base64.RawURLEncoding (A-Z a-z 0-9 - _). Strip any trailing bytes (e.g. from CDN compression).
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteByte(c)
			continue
		}
		break
	}
	token := b.String()
	if token == "" {
		return "", errors.New("empty token")
	}
	return token, nil
}

type httpStreamConn struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc

	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *httpStreamConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *httpStreamConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *httpStreamConn) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	_ = c.writer.CloseWithError(io.ErrClosedPipe)
	return c.reader.Close()
}

func (c *httpStreamConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *httpStreamConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *httpStreamConn) SetDeadline(time.Time) error      { return nil }
func (c *httpStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *httpStreamConn) SetWriteDeadline(time.Time) error { return nil }

func dialXHTTP(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	// Prefer split-xhttp (Cloudflare-friendly). Fall back to stream-one for older servers / environments.
	c, errSplit := dialXHTTPSplit(ctx, serverAddress, opts)
	if errSplit == nil {
		return c, nil
	}
	c2, errOne := dialXHTTPStreamOne(ctx, serverAddress, opts)
	if errOne == nil {
		return c2, nil
	}
	return nil, fmt.Errorf("dial xhttp failed: split: %v; stream-one: %w", errSplit, errOne)
}

func dialXHTTPStreamOne(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	scheme, urlHost, dialAddr, serverName, err := normalizeHTTPDialTarget(serverAddress, opts.TLSEnabled, opts.HostOverride)
	if err != nil {
		return nil, err
	}
	headerHost := canonicalHeaderHost(urlHost, scheme)

	r := rngPool.Get().(*mrand.Rand)
	path := paths[r.Intn(len(paths))]
	ctype := contentTypes[r.Intn(len(contentTypes))]
	ua := userAgents[r.Intn(len(userAgents))]
	accept := accepts[r.Intn(len(accepts))]
	lang := acceptLanguages[r.Intn(len(acceptLanguages))]
	enc := acceptEncodings[r.Intn(len(acceptEncodings))]
	rngPool.Put(r)

	u := url.URL{
		Scheme: scheme,
		Host:   urlHost,
		Path:   path,
	}

	reqBodyR, reqBodyW := io.Pipe()

	ctx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), reqBodyR)
	if err != nil {
		cancel()
		_ = reqBodyW.Close()
		return nil, err
	}
	req.Host = headerHost

	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", lang)
	req.Header.Set("Accept-Encoding", enc)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("X-Sudoku-Tunnel", string(TunnelModeXHTTP))
	req.Header.Set("X-Sudoku-Version", "1")

	dialFn := opts.DialContext
	if dialFn == nil {
		dialFn = (&net.Dialer{}).DialContext
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        16,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			if addr == urlHost {
				addr = dialAddr
			}
			return dialFn(dialCtx, network, addr)
		},
	}
	if scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Do(req)
	if err != nil {
		cancel()
		_ = reqBodyW.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		cancel()
		_ = reqBodyW.Close()
		return nil, fmt.Errorf("xhttp bad status: %s (%s)", resp.Status, strings.TrimSpace(string(body)))
	}

	return &httpStreamConn{
		reader:     resp.Body,
		writer:     reqBodyW,
		cancel:     cancel,
		localAddr:  &net.TCPAddr{},
		remoteAddr: &net.TCPAddr{},
	}, nil
}

type xhttpSplitConn struct {
	ctx    context.Context
	cancel context.CancelFunc

	client     *http.Client
	pushURL    string
	pullURL    string
	closeURL   string
	headerHost string

	rxc    chan []byte
	closed chan struct{}

	writeCh chan []byte

	mu         sync.Mutex
	readBuf    []byte
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *xhttpSplitConn) Read(b []byte) (n int, err error) {
	if len(c.readBuf) == 0 {
		select {
		case c.readBuf = <-c.rxc:
		case <-c.closed:
			return 0, io.ErrClosedPipe
		}
	}
	n = copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *xhttpSplitConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	default:
	}
	c.mu.Unlock()

	payload := make([]byte, len(b))
	copy(payload, b)
	select {
	case c.writeCh <- payload:
		return len(b), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

func (c *xhttpSplitConn) Close() error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil
	default:
		close(c.closed)
	}
	c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
	}

	// Best-effort session close signal (avoid leaking server-side sessions).
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(closeCtx, http.MethodPost, c.closeURL, nil)
	if err == nil {
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModeXHTTP)
		if resp, doErr := c.client.Do(req); doErr == nil && resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
			_ = resp.Body.Close()
		}
	}

	return nil
}

func (c *xhttpSplitConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *xhttpSplitConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *xhttpSplitConn) SetDeadline(time.Time) error      { return nil }
func (c *xhttpSplitConn) SetReadDeadline(time.Time) error  { return nil }
func (c *xhttpSplitConn) SetWriteDeadline(time.Time) error { return nil }

func dialXHTTPSplit(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	scheme, urlHost, dialAddr, serverName, err := normalizeHTTPDialTarget(serverAddress, opts.TLSEnabled, opts.HostOverride)
	if err != nil {
		return nil, err
	}
	headerHost := canonicalHeaderHost(urlHost, scheme)

	dialFn := opts.DialContext
	if dialFn == nil {
		dialFn = (&net.Dialer{}).DialContext
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        32,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			if addr == urlHost {
				addr = dialAddr
			}
			return dialFn(dialCtx, network, addr)
		},
	}
	if scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Transport: transport,
	}

	authorizeURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: "/session"}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = headerHost
	applyTunnelHeaders(req.Header, headerHost, TunnelModeXHTTP)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xhttp authorize bad status: %s (%s)", resp.Status, strings.TrimSpace(string(bodyBytes)))
	}

	token, err := parseTunnelToken(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("xhttp authorize failed: %q", strings.TrimSpace(string(bodyBytes)))
	}
	if token == "" {
		return nil, fmt.Errorf("xhttp authorize empty token")
	}

	pushURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: "/api/v1/upload", RawQuery: "token=" + url.QueryEscape(token)}).String()
	pullURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: "/stream", RawQuery: "token=" + url.QueryEscape(token)}).String()
	closeURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: "/api/v1/upload", RawQuery: "token=" + url.QueryEscape(token) + "&close=1"}).String()

	connCtx, cancel := context.WithCancel(context.Background())
	c := &xhttpSplitConn{
		ctx:        connCtx,
		cancel:     cancel,
		client:     client,
		pushURL:    pushURL,
		pullURL:    pullURL,
		closeURL:   closeURL,
		headerHost: headerHost,
		rxc:        make(chan []byte, 256),
		closed:     make(chan struct{}),
		writeCh:    make(chan []byte, 256),
		localAddr:  &net.TCPAddr{},
		remoteAddr: &net.TCPAddr{},
	}

	go c.pullLoop()
	go c.pushLoop()
	return c, nil
}

func (c *xhttpSplitConn) pullLoop() {
	const (
		requestTimeout = 30 * time.Second
		readChunkSize  = 32 * 1024
		idleBackoff    = 25 * time.Millisecond
	)

	buf := make([]byte, readChunkSize)
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		reqCtx, cancel := context.WithTimeout(c.ctx, requestTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, c.pullURL, nil)
		if err != nil {
			cancel()
			_ = c.Close()
			return
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModeXHTTP)

		resp, err := c.client.Do(req)
		if err != nil {
			cancel()
			_ = c.Close()
			return
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			cancel()
			_ = c.Close()
			return
		}

		readAny := false
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				readAny = true
				payload := make([]byte, n)
				copy(payload, buf[:n])
				select {
				case c.rxc <- payload:
				case <-c.closed:
					_ = resp.Body.Close()
					return
				}
			}
			if rerr != nil {
				_ = resp.Body.Close()
				cancel()
				if errors.Is(rerr, io.EOF) {
					// Long-poll ended; retry.
					break
				}
				_ = c.Close()
				return
			}
		}
		cancel()
		if !readAny {
			// Avoid tight loop if the server replied quickly with an empty body.
			select {
			case <-time.After(idleBackoff):
			case <-c.closed:
				return
			}
		}
	}
}

func (c *xhttpSplitConn) pushLoop() {
	const (
		maxBatchBytes  = 256 * 1024
		flushInterval  = 5 * time.Millisecond
		requestTimeout = 20 * time.Second
	)

	var (
		buf   bytes.Buffer
		timer = time.NewTimer(flushInterval)
	)
	defer timer.Stop()

	flush := func() bool {
		if buf.Len() == 0 {
			return true
		}

		reqCtx, cancel := context.WithTimeout(c.ctx, requestTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.pushURL, bytes.NewReader(buf.Bytes()))
		if err != nil {
			cancel()
			return false
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModeXHTTP)
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := c.client.Do(req)
		if err != nil {
			cancel()
			return false
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode != http.StatusOK {
			return false
		}

		buf.Reset()
		return true
	}

	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(flushInterval)
	}

	resetTimer()

	for {
		select {
		case b, ok := <-c.writeCh:
			if !ok {
				_ = flush()
				return
			}
			if len(b) == 0 {
				continue
			}
			if buf.Len()+len(b) > maxBatchBytes {
				if !flush() {
					_ = c.Close()
					return
				}
				resetTimer()
			}
			_, _ = buf.Write(b)
			if buf.Len() >= maxBatchBytes {
				if !flush() {
					_ = c.Close()
					return
				}
				resetTimer()
			}
		case <-timer.C:
			if !flush() {
				_ = c.Close()
				return
			}
			resetTimer()
		case <-c.closed:
			_ = flush()
			return
		}
	}
}

type phtConn struct {
	client     *http.Client
	pushURL    string
	pullURL    string
	closeURL   string
	headerHost string

	rxc    chan []byte
	closed chan struct{}

	writeCh chan []byte

	mu         sync.Mutex
	readBuf    []byte
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *phtConn) Read(b []byte) (n int, err error) {
	if len(c.readBuf) == 0 {
		select {
		case c.readBuf = <-c.rxc:
		case <-c.closed:
			return 0, io.ErrClosedPipe
		}
	}
	n = copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *phtConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	default:
	}
	c.mu.Unlock()

	payload := make([]byte, len(b))
	copy(payload, b)
	select {
	case c.writeCh <- payload:
		return len(b), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

func (c *phtConn) Close() error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil
	default:
		close(c.closed)
	}
	c.mu.Unlock()

	close(c.writeCh)

	// Best-effort session close signal (avoid leaking server-side sessions).
	req, err := http.NewRequest(http.MethodPost, c.closeURL, nil)
	if err == nil {
		req.Host = c.headerHost
		req.Header.Set("X-Sudoku-Tunnel", string(TunnelModePHT))
		req.Header.Set("X-Sudoku-Version", "1")
		_, _ = c.client.Do(req)
	}

	return nil
}

func (c *phtConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *phtConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *phtConn) SetDeadline(time.Time) error      { return nil }
func (c *phtConn) SetReadDeadline(time.Time) error  { return nil }
func (c *phtConn) SetWriteDeadline(time.Time) error { return nil }

func dialPHT(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	scheme, urlHost, dialAddr, serverName, err := normalizeHTTPDialTarget(serverAddress, opts.TLSEnabled, opts.HostOverride)
	if err != nil {
		return nil, err
	}
	headerHost := canonicalHeaderHost(urlHost, scheme)

	dialFn := opts.DialContext
	if dialFn == nil {
		dialFn = (&net.Dialer{}).DialContext
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        32,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			if addr == urlHost {
				addr = dialAddr
			}
			return dialFn(dialCtx, network, addr)
		},
	}
	if scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Transport: transport,
	}

	authorizeURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: "/session"}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = headerHost
	applyTunnelHeaders(req.Header, headerHost, TunnelModePHT)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pht authorize bad status: %s (%s)", resp.Status, strings.TrimSpace(string(bodyBytes)))
	}

	token, err := parseTunnelToken(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("pht authorize failed: %q", strings.TrimSpace(string(bodyBytes)))
	}
	if token == "" {
		return nil, fmt.Errorf("pht authorize empty token")
	}

	pushURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: "/api/v1/upload", RawQuery: "token=" + url.QueryEscape(token)}).String()
	pullURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: "/stream", RawQuery: "token=" + url.QueryEscape(token)}).String()
	closeURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: "/api/v1/upload", RawQuery: "token=" + url.QueryEscape(token) + "&close=1"}).String()

	c := &phtConn{
		client:     client,
		pushURL:    pushURL,
		pullURL:    pullURL,
		closeURL:   closeURL,
		headerHost: headerHost,
		rxc:        make(chan []byte, 128),
		closed:     make(chan struct{}),
		writeCh:    make(chan []byte, 256),
		localAddr:  &net.TCPAddr{},
		remoteAddr: &net.TCPAddr{},
	}

	go c.pullLoop()
	go c.pushLoop()
	return c, nil
}

func (c *phtConn) pullLoop() {
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		req, err := http.NewRequest(http.MethodGet, c.pullURL, nil)
		if err != nil {
			_ = c.Close()
			return
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModePHT)

		resp, err := c.client.Do(req)
		if err != nil {
			_ = c.Close()
			return
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			_ = c.Close()
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			payload, err := base64.StdEncoding.DecodeString(line)
			if err != nil {
				_ = resp.Body.Close()
				_ = c.Close()
				return
			}
			select {
			case c.rxc <- payload:
			case <-c.closed:
				_ = resp.Body.Close()
				return
			}
		}
		_ = resp.Body.Close()
		if err := scanner.Err(); err != nil {
			_ = c.Close()
			return
		}
	}
}

func (c *phtConn) pushLoop() {
	const (
		maxBatchBytes   = 64 * 1024
		flushInterval   = 5 * time.Millisecond
		maxLineRawBytes = 16 * 1024
	)

	var (
		buf        bytes.Buffer
		pendingRaw int
		timer      = time.NewTimer(flushInterval)
	)
	defer timer.Stop()

	flush := func() bool {
		if buf.Len() == 0 {
			return true
		}

		req, err := http.NewRequest(http.MethodPost, c.pushURL, bytes.NewReader(buf.Bytes()))
		if err != nil {
			return false
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModePHT)
		req.Header.Set("Content-Type", "text/plain")

		resp, err := c.client.Do(req)
		if err != nil {
			return false
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}

		buf.Reset()
		pendingRaw = 0
		return true
	}

	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(flushInterval)
	}

	resetTimer()

	for {
		select {
		case b, ok := <-c.writeCh:
			if !ok {
				_ = flush()
				return
			}
			if len(b) == 0 {
				continue
			}

			// Split large writes into multiple base64 lines to cap per-line size.
			for len(b) > 0 {
				chunk := b
				if len(chunk) > maxLineRawBytes {
					chunk = b[:maxLineRawBytes]
				}
				b = b[len(chunk):]

				encLen := base64.StdEncoding.EncodedLen(len(chunk))
				if pendingRaw+len(chunk) > maxBatchBytes || buf.Len()+encLen+1 > maxBatchBytes*2 {
					if !flush() {
						_ = c.Close()
						return
					}
				}

				tmp := make([]byte, base64.StdEncoding.EncodedLen(len(chunk)))
				base64.StdEncoding.Encode(tmp, chunk)
				buf.Write(tmp)
				buf.WriteByte('\n')
				pendingRaw += len(chunk)
			}

			if pendingRaw >= maxBatchBytes {
				if !flush() {
					_ = c.Close()
					return
				}
				resetTimer()
			}
		case <-timer.C:
			if !flush() {
				_ = c.Close()
				return
			}
			resetTimer()
		case <-c.closed:
			_ = flush()
			return
		}
	}
}

func normalizeHTTPDialTarget(serverAddress string, tlsEnabled bool, hostOverride string) (scheme, urlHost, dialAddr, serverName string, err error) {
	host, port, err := net.SplitHostPort(serverAddress)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid server address %q: %w", serverAddress, err)
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

	if tlsEnabled || port == "443" {
		scheme = "https"
	} else {
		scheme = "http"
	}

	dialAddr = net.JoinHostPort(host, port)
	return scheme, urlHost, dialAddr, trimPortForHost(serverName), nil
}

func applyTunnelHeaders(h http.Header, host string, mode TunnelMode) {
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
	h.Set("Connection", "keep-alive")
	h.Set("Host", host)
	h.Set("X-Sudoku-Tunnel", string(mode))
	h.Set("X-Sudoku-Version", "1")
}

type TunnelServerOptions struct {
	Mode string
	// PHTPullReadTimeout controls how long the server long-poll waits for tunnel downlink data before replying with a keepalive newline.
	PHTPullReadTimeout time.Duration
	// PHTSessionTTL is a best-effort TTL to prevent leaked sessions. 0 uses a conservative default.
	PHTSessionTTL time.Duration
}

type TunnelServer struct {
	mode TunnelMode

	phtPullReadTimeout time.Duration
	phtSessionTTL      time.Duration

	mu       sync.Mutex
	sessions map[string]*phtSession
}

type phtSession struct {
	conn       net.Conn
	lastActive time.Time
}

func NewTunnelServer(opts TunnelServerOptions) *TunnelServer {
	mode := normalizeTunnelMode(opts.Mode)
	if mode == TunnelModeLegacy {
		// Server-side "legacy" means: don't accept xhttp/pht; only passthrough.
	}
	timeout := opts.PHTPullReadTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ttl := opts.PHTSessionTTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &TunnelServer{
		mode:               mode,
		phtPullReadTimeout: timeout,
		phtSessionTTL:      ttl,
		sessions:           make(map[string]*phtSession),
	}
}

// HandleConn inspects rawConn. If it is an HTTP tunnel request (xhttp/pht), it is handled here and:
//   - returns HandleStartTunnel + a net.Conn that carries the raw Sudoku stream (xhttp stream or pht session pipe)
//   - or returns HandleDone if the HTTP request is a pht control request (push/pull) and no Sudoku handshake should run on this TCP conn
//
// If it is not an HTTP tunnel request (or server mode is legacy), it returns HandlePassThrough with a conn that replays any pre-read bytes.
func (s *TunnelServer) HandleConn(rawConn net.Conn) (HandleResult, net.Conn, error) {
	if rawConn == nil {
		return HandleDone, nil, errors.New("nil conn")
	}

	// Small header read deadline to avoid stalling Accept loops. The actual Sudoku handshake has its own deadlines.
	_ = rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var first [4]byte
	n, err := io.ReadFull(rawConn, first[:])
	if err != nil {
		_ = rawConn.SetReadDeadline(time.Time{})
		// Even if short-read, preserve bytes for downstream handlers.
		if n > 0 {
			return HandlePassThrough, newPreBufferedConn(rawConn, first[:n]), nil
		}
		return HandleDone, nil, err
	}
	pc := newPreBufferedConn(rawConn, first[:])
	br := bufio.NewReader(pc)

	if !LooksLikeHTTPRequestStart(first[:]) {
		_ = rawConn.SetReadDeadline(time.Time{})
		return HandlePassThrough, pc, nil
	}

	req, headerBytes, buffered, err := readHTTPHeader(br)
	_ = rawConn.SetReadDeadline(time.Time{})
	if err != nil {
		// Not a valid HTTP request; hand it back to the legacy path with replay.
		prefix := make([]byte, 0, len(first)+len(headerBytes)+len(buffered))
		if len(headerBytes) == 0 || !bytes.HasPrefix(headerBytes, first[:]) {
			prefix = append(prefix, first[:]...)
		}
		prefix = append(prefix, headerBytes...)
		prefix = append(prefix, buffered...)
		return HandlePassThrough, newPreBufferedConn(rawConn, prefix), nil
	}

	tunnelHeader := strings.ToLower(strings.TrimSpace(req.headers["x-sudoku-tunnel"]))
	if tunnelHeader == "" {
		// Not our tunnel; replay full bytes to legacy handler.
		prefix := make([]byte, 0, len(headerBytes)+len(buffered))
		prefix = append(prefix, headerBytes...)
		prefix = append(prefix, buffered...)
		return HandlePassThrough, newPreBufferedConn(rawConn, prefix), nil
	}
	if s.mode == TunnelModeLegacy {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusNotFound, "not found")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	switch TunnelMode(tunnelHeader) {
	case TunnelModeXHTTP:
		if s.mode != TunnelModeXHTTP && s.mode != TunnelModeAuto {
			_ = writeSimpleHTTPResponse(rawConn, http.StatusNotFound, "not found")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
		return s.handleXHTTP(rawConn, req, buffered)
	case TunnelModePHT:
		if s.mode != TunnelModePHT && s.mode != TunnelModeAuto {
			_ = writeSimpleHTTPResponse(rawConn, http.StatusNotFound, "not found")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
		return s.handlePHT(rawConn, req, buffered)
	default:
		_ = writeSimpleHTTPResponse(rawConn, http.StatusNotFound, "not found")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}
}

type httpRequestHeader struct {
	method  string
	target  string // path + query
	proto   string
	headers map[string]string // lower-case keys
}

func readHTTPHeader(r *bufio.Reader) (*httpRequestHeader, []byte, []byte, error) {
	const maxHeaderBytes = 32 * 1024

	var consumed bytes.Buffer
	readLine := func() ([]byte, error) {
		line, err := r.ReadSlice('\n')
		if len(line) > 0 {
			if consumed.Len()+len(line) > maxHeaderBytes {
				return line, fmt.Errorf("http header too large")
			}
			consumed.Write(line)
		}
		return line, err
	}

	// Request line
	line, err := readLine()
	if err != nil {
		return nil, consumed.Bytes(), readAllBuffered(r), err
	}
	lineStr := strings.TrimRight(string(line), "\r\n")
	parts := strings.SplitN(lineStr, " ", 3)
	if len(parts) != 3 {
		return nil, consumed.Bytes(), readAllBuffered(r), fmt.Errorf("invalid request line")
	}
	req := &httpRequestHeader{
		method:  parts[0],
		target:  parts[1],
		proto:   parts[2],
		headers: make(map[string]string),
	}

	// Headers
	for {
		line, err = readLine()
		if err != nil {
			return nil, consumed.Bytes(), readAllBuffered(r), err
		}
		trimmed := strings.TrimRight(string(line), "\r\n")
		if trimmed == "" {
			break
		}
		k, v, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k == "" {
			continue
		}
		// Keep the first value; we only care about a small set.
		if _, exists := req.headers[k]; !exists {
			req.headers[k] = v
		}
	}

	return req, consumed.Bytes(), readAllBuffered(r), nil
}

func readAllBuffered(r *bufio.Reader) []byte {
	n := r.Buffered()
	if n <= 0 {
		return nil
	}
	b, err := r.Peek(n)
	if err != nil {
		return nil
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}

type preBufferedConn struct {
	net.Conn
	buf []byte
}

func newPreBufferedConn(conn net.Conn, pre []byte) net.Conn {
	cpy := make([]byte, len(pre))
	copy(cpy, pre)
	return &preBufferedConn{Conn: conn, buf: cpy}
}

func (p *preBufferedConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

type bodyConn struct {
	net.Conn
	reader io.Reader
	writer io.WriteCloser
	tail   io.Writer
	flush  func() error
}

func (c *bodyConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bodyConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if c.flush != nil {
		_ = c.flush()
	}
	return n, err
}

func (c *bodyConn) Close() error {
	var firstErr error
	if c.writer != nil {
		if err := c.writer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		// NewChunkedWriter does not write the final CRLF. Ensure a clean terminator.
		if c.tail != nil {
			_, _ = c.tail.Write([]byte("\r\n"))
		} else {
			_, _ = c.Conn.Write([]byte("\r\n"))
		}
		if c.flush != nil {
			_ = c.flush()
		}
	}
	if err := c.Conn.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (s *TunnelServer) handleXHTTP(rawConn net.Conn, req *httpRequestHeader, buffered []byte) (HandleResult, net.Conn, error) {
	u, err := url.ParseRequestURI(req.target)
	if err != nil {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "bad request")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	// Only accept plausible paths to reduce accidental exposure.
	if !isAllowedPath(req.target) {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusNotFound, "not found")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	token := u.Query().Get("token")
	closeFlag := u.Query().Get("close") == "1"

	switch strings.ToUpper(req.method) {
	case http.MethodGet:
		// XHTTP Split Session: GET /session (no token) => token + start tunnel on a server-side pipe.
		if token == "" && u.Path == "/session" {
			return s.phtAuthorize(rawConn)
		}
		// XHTTP Split Session: GET /stream?token=... => downlink poll.
		if token != "" && u.Path == "/stream" {
			return s.xhttpPull(rawConn, token)
		}
		_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "bad request")
		_ = rawConn.Close()
		return HandleDone, nil, nil

	case http.MethodPost:
		// XHTTP Split Session: POST /api/v1/upload?token=... => uplink push.
		if token != "" && u.Path == "/api/v1/upload" {
			if closeFlag {
				s.phtClose(token)
				_ = writeSimpleHTTPResponse(rawConn, http.StatusOK, "")
				_ = rawConn.Close()
				return HandleDone, nil, nil
			}
			bodyReader, err := newRequestBodyReader(newPreBufferedConn(rawConn, buffered), req.headers)
			if err != nil {
				_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "bad request")
				_ = rawConn.Close()
				return HandleDone, nil, nil
			}
			return s.xhttpPush(rawConn, token, bodyReader)
		}

		// XHTTP Stream-One: single full-duplex POST.
		if err := writeXHTTPResponseHeader(rawConn); err != nil {
			_ = rawConn.Close()
			return HandleDone, nil, err
		}

		bodyReader, err := newRequestBodyReader(newPreBufferedConn(rawConn, buffered), req.headers)
		if err != nil {
			_ = rawConn.Close()
			return HandleDone, nil, err
		}

		bw := bufio.NewWriterSize(rawConn, 32*1024)
		chunked := httputil.NewChunkedWriter(bw)
		stream := &bodyConn{
			Conn:   rawConn,
			reader: bodyReader,
			writer: chunked,
			tail:   bw,
			flush:  bw.Flush,
		}
		return HandleStartTunnel, stream, nil

	default:
		_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "bad request")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}
}

func isAllowedPath(target string) bool {
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return false
	}
	for _, p := range paths {
		if u.Path == p {
			return true
		}
	}
	return false
}

func newRequestBodyReader(conn net.Conn, headers map[string]string) (io.Reader, error) {
	br := bufio.NewReaderSize(conn, 32*1024)

	te := strings.ToLower(headers["transfer-encoding"])
	if strings.Contains(te, "chunked") {
		return httputil.NewChunkedReader(br), nil
	}
	if clStr := headers["content-length"]; clStr != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(clStr), 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid content-length")
		}
		return io.LimitReader(br, n), nil
	}
	return br, nil
}

func writeXHTTPResponseHeader(w io.Writer) error {
	_, err := io.WriteString(w,
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Cache-Control: no-store\r\n"+
			"Pragma: no-cache\r\n"+
			"Connection: keep-alive\r\n"+
			"X-Accel-Buffering: no\r\n"+
			"\r\n")
	return err
}

func writeSimpleHTTPResponse(w io.Writer, code int, body string) error {
	if body == "" {
		body = http.StatusText(code)
	}
	body = strings.TrimRight(body, "\r\n")
	_, err := io.WriteString(w,
		fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			code, http.StatusText(code), len(body), body))
	return err
}

func writeTokenHTTPResponse(w io.Writer, token string) error {
	token = strings.TrimRight(token, "\r\n")
	// Use application/octet-stream to avoid CDN auto-compression (e.g. brotli) breaking clients that expect a plain token string.
	_, err := io.WriteString(w,
		fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nPragma: no-cache\r\nContent-Length: %d\r\nConnection: close\r\n\r\ntoken=%s",
			len("token=")+len(token), token))
	return err
}

func (s *TunnelServer) handlePHT(rawConn net.Conn, req *httpRequestHeader, buffered []byte) (HandleResult, net.Conn, error) {
	u, err := url.ParseRequestURI(req.target)
	if err != nil {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "bad request")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	if !isAllowedPath(req.target) {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusNotFound, "not found")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	token := u.Query().Get("token")
	closeFlag := u.Query().Get("close") == "1"
	switch strings.ToUpper(req.method) {
	case http.MethodGet:
		if token == "" {
			return s.phtAuthorize(rawConn)
		}
		return s.phtPull(rawConn, token)
	case http.MethodPost:
		if token == "" {
			_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "missing token")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
		if closeFlag {
			s.phtClose(token)
			_ = writeSimpleHTTPResponse(rawConn, http.StatusOK, "")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
		bodyReader, err := newRequestBodyReader(newPreBufferedConn(rawConn, buffered), req.headers)
		if err != nil {
			_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "bad request")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
		return s.phtPush(rawConn, token, bodyReader)
	default:
		_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "bad request")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}
}

func (s *TunnelServer) phtAuthorize(rawConn net.Conn) (HandleResult, net.Conn, error) {
	token, err := newPHTToken()
	if err != nil {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusInternalServerError, "internal error")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	c1, c2 := net.Pipe()

	s.mu.Lock()
	s.sessions[token] = &phtSession{conn: c2, lastActive: time.Now()}
	s.mu.Unlock()

	go s.reapLater(token)

	_ = writeTokenHTTPResponse(rawConn, token)
	_ = rawConn.Close()
	return HandleStartTunnel, c1, nil
}

func newPHTToken() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (s *TunnelServer) reapLater(token string) {
	ttl := s.phtSessionTTL
	if ttl <= 0 {
		return
	}
	timer := time.NewTimer(ttl)
	defer timer.Stop()
	<-timer.C

	s.mu.Lock()
	sess, ok := s.sessions[token]
	if !ok {
		s.mu.Unlock()
		return
	}
	if time.Since(sess.lastActive) < ttl {
		s.mu.Unlock()
		return
	}
	delete(s.sessions, token)
	s.mu.Unlock()
	_ = sess.conn.Close()
}

func (s *TunnelServer) phtGet(token string) (*phtSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	sess.lastActive = time.Now()
	return sess, true
}

func (s *TunnelServer) phtClose(token string) {
	s.mu.Lock()
	sess, ok := s.sessions[token]
	if ok {
		delete(s.sessions, token)
	}
	s.mu.Unlock()
	if ok {
		_ = sess.conn.Close()
	}
}

func (s *TunnelServer) phtPush(rawConn net.Conn, token string, body io.Reader) (HandleResult, net.Conn, error) {
	sess, ok := s.phtGet(token)
	if !ok {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusForbidden, "forbidden")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	payload, err := io.ReadAll(io.LimitReader(body, 1<<20)) // 1MiB per request cap
	if err != nil {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "bad request")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	lines := bytes.Split(payload, []byte{'\n'})
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(line)))
		n, decErr := base64.StdEncoding.Decode(decoded, line)
		if decErr != nil {
			_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "bad request")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
		if n == 0 {
			continue
		}
		_ = sess.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, werr := sess.conn.Write(decoded[:n])
		_ = sess.conn.SetWriteDeadline(time.Time{})
		if werr != nil {
			s.phtClose(token)
			_ = writeSimpleHTTPResponse(rawConn, http.StatusGone, "gone")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
	}

	_ = writeSimpleHTTPResponse(rawConn, http.StatusOK, "")
	_ = rawConn.Close()
	return HandleDone, nil, nil
}

func (s *TunnelServer) xhttpPush(rawConn net.Conn, token string, body io.Reader) (HandleResult, net.Conn, error) {
	sess, ok := s.phtGet(token)
	if !ok {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusForbidden, "forbidden")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	const maxUploadBytes = 1 << 20
	payload, err := io.ReadAll(io.LimitReader(body, maxUploadBytes+1))
	if err != nil {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusBadRequest, "bad request")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}
	if len(payload) > maxUploadBytes {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusRequestEntityTooLarge, "too large")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	if len(payload) > 0 {
		_ = sess.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, werr := sess.conn.Write(payload)
		_ = sess.conn.SetWriteDeadline(time.Time{})
		if werr != nil {
			s.phtClose(token)
			_ = writeSimpleHTTPResponse(rawConn, http.StatusGone, "gone")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
	}

	_ = writeSimpleHTTPResponse(rawConn, http.StatusOK, "")
	_ = rawConn.Close()
	return HandleDone, nil, nil
}

func (s *TunnelServer) xhttpPull(rawConn net.Conn, token string) (HandleResult, net.Conn, error) {
	sess, ok := s.phtGet(token)
	if !ok {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusForbidden, "forbidden")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	// Streaming response (chunked) with raw bytes (no base64 framing).
	if err := writeXHTTPResponseHeader(rawConn); err != nil {
		_ = rawConn.Close()
		return HandleDone, nil, err
	}

	bw := bufio.NewWriterSize(rawConn, 32*1024)
	cw := httputil.NewChunkedWriter(bw)
	defer func() {
		_ = cw.Close()
		_, _ = bw.WriteString("\r\n")
		_ = bw.Flush()
		_ = rawConn.Close()
	}()

	buf := make([]byte, 32*1024)
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(s.phtPullReadTimeout))
		n, err := sess.conn.Read(buf)
		if n > 0 {
			_, _ = cw.Write(buf[:n])
			_ = bw.Flush()
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// End this long-poll response; client will re-issue.
				return HandleDone, nil, nil
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				return HandleDone, nil, nil
			}
			s.phtClose(token)
			return HandleDone, nil, nil
		}
	}
}

func (s *TunnelServer) phtPull(rawConn net.Conn, token string) (HandleResult, net.Conn, error) {
	sess, ok := s.phtGet(token)
	if !ok {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusForbidden, "forbidden")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	// Streaming response (chunked) with base64 lines.
	if err := writeXHTTPResponseHeader(rawConn); err != nil {
		_ = rawConn.Close()
		return HandleDone, nil, err
	}

	bw := bufio.NewWriterSize(rawConn, 32*1024)
	cw := httputil.NewChunkedWriter(bw)
	defer func() {
		_ = cw.Close()
		_, _ = bw.WriteString("\r\n")
		_ = bw.Flush()
		_ = rawConn.Close()
	}()

	buf := make([]byte, 32*1024)
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(s.phtPullReadTimeout))
		n, err := sess.conn.Read(buf)
		if n > 0 {
			line := make([]byte, base64.StdEncoding.EncodedLen(n))
			base64.StdEncoding.Encode(line, buf[:n])
			_, _ = cw.Write(append(line, '\n'))
			_ = bw.Flush()
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// Keepalive: send an empty line then end this long-poll response.
				_, _ = cw.Write([]byte("\n"))
				_ = bw.Flush()
				return HandleDone, nil, nil
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				return HandleDone, nil, nil
			}
			s.phtClose(token)
			return HandleDone, nil, nil
		}
	}
}
