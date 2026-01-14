package httpmask

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httputil"
	"github.com/metacubex/tls"
)

type TunnelMode string

const (
	TunnelModeLegacy TunnelMode = "legacy"
	TunnelModeStream TunnelMode = "stream"
	TunnelModePoll   TunnelMode = "poll"
	TunnelModeAuto   TunnelMode = "auto"
)

func normalizeTunnelMode(mode string) TunnelMode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", string(TunnelModeLegacy):
		return TunnelModeLegacy
	case string(TunnelModeStream):
		return TunnelModeStream
	case string(TunnelModePoll):
		return TunnelModePoll
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
	TLSEnabled   bool   // when true, use HTTPS; otherwise, use HTTP (no port-based inference)
	HostOverride string // optional Host header / SNI host (without scheme); accepts "example.com" or "example.com:443"
	// PathRoot is an optional first-level path prefix for all HTTP tunnel endpoints.
	// Example: "aabbcc" => "/aabbcc/session", "/aabbcc/api/v1/upload", ...
	PathRoot string
	// AuthKey enables short-term HMAC auth for HTTP tunnel requests (anti-probing).
	// When set (non-empty), each HTTP request carries an Authorization bearer token derived from AuthKey.
	AuthKey string
	// Upgrade optionally wraps the raw tunnel conn and/or writes a small prelude before DialTunnel returns.
	// It is called with the raw tunnel conn; if it returns a non-nil conn, that conn is returned by DialTunnel.
	Upgrade func(raw net.Conn) (net.Conn, error)
	// Multiplex controls whether the caller should reuse underlying HTTP connections (HTTP/1.1 keep-alive / HTTP/2).
	// To reuse across multiple dials, create a TunnelClient per proxy and reuse it.
	// Values: "off" disables reuse; "auto"/"on" enables it.
	Multiplex string
	// DialContext overrides how the HTTP tunnel dials raw TCP/TLS connections.
	// It must not be nil; passing nil is a programming error.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

type TunnelClientOptions struct {
	TLSEnabled   bool
	HostOverride string
	DialContext  func(ctx context.Context, network, addr string) (net.Conn, error)
	MaxIdleConns int
}

type TunnelClient struct {
	client    *http.Client
	transport *http.Transport
	target    httpClientTarget
}

func NewTunnelClient(serverAddress string, opts TunnelClientOptions) (*TunnelClient, error) {
	maxIdle := opts.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 32
	}

	transport, target, err := buildHTTPTransport(serverAddress, opts.TLSEnabled, opts.HostOverride, opts.DialContext, maxIdle)
	if err != nil {
		return nil, err
	}

	return &TunnelClient{
		client:    &http.Client{Transport: transport},
		transport: transport,
		target:    target,
	}, nil
}

func (c *TunnelClient) CloseIdleConnections() {
	if c == nil || c.transport == nil {
		return
	}
	c.transport.CloseIdleConnections()
}

func (c *TunnelClient) DialTunnel(ctx context.Context, opts TunnelDialOptions) (net.Conn, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("nil tunnel client")
	}
	tm := normalizeTunnelMode(opts.Mode)
	if tm == TunnelModeLegacy {
		return nil, fmt.Errorf("legacy mode does not use http tunnel")
	}

	switch tm {
	case TunnelModeStream:
		return dialStreamWithClient(ctx, c.client, c.target, opts)
	case TunnelModePoll:
		return dialPollWithClient(ctx, c.client, c.target, opts)
	case TunnelModeAuto:
		streamCtx, cancelX := context.WithTimeout(ctx, 3*time.Second)
		c1, errX := dialStreamWithClient(streamCtx, c.client, c.target, opts)
		cancelX()
		if errX == nil {
			return c1, nil
		}
		c2, errP := dialPollWithClient(ctx, c.client, c.target, opts)
		if errP == nil {
			return c2, nil
		}
		return nil, fmt.Errorf("auto tunnel failed: stream: %v; poll: %w", errX, errP)
	default:
		return dialStreamWithClient(ctx, c.client, c.target, opts)
	}
}

// DialTunnel establishes a bidirectional stream over HTTP:
//   - stream: a single streaming POST (request body uplink, response body downlink)
//   - poll: authorize + push/pull polling tunnel (base64 framed)
//   - auto: try stream then fall back to poll
//
// The returned net.Conn carries the raw Sudoku stream (no HTTP headers).
func DialTunnel(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	mode := normalizeTunnelMode(opts.Mode)
	if mode == TunnelModeLegacy {
		return nil, fmt.Errorf("legacy mode does not use http tunnel")
	}

	switch mode {
	case TunnelModeStream:
		return dialStreamFn(ctx, serverAddress, opts)
	case TunnelModePoll:
		return dialPollFn(ctx, serverAddress, opts)
	case TunnelModeAuto:
		// "stream" can hang on some CDNs that buffer uploads until request body completes.
		// Keep it on a short leash so we can fall back to poll within the caller's deadline.
		streamCtx, cancelX := context.WithTimeout(ctx, 3*time.Second)
		c, errX := dialStreamFn(streamCtx, serverAddress, opts)
		cancelX()
		if errX == nil {
			return c, nil
		}
		c, errP := dialPollFn(ctx, serverAddress, opts)
		if errP == nil {
			return c, nil
		}
		return nil, fmt.Errorf("auto tunnel failed: stream: %v; poll: %w", errX, errP)
	default:
		return dialStreamFn(ctx, serverAddress, opts)
	}
}

var (
	dialStreamFn = dialStream
	dialPollFn   = dialPoll
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
	if c.writer != nil {
		_ = c.writer.CloseWithError(io.ErrClosedPipe)
	}
	if c.reader != nil {
		return c.reader.Close()
	}
	return nil
}

func (c *httpStreamConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *httpStreamConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *httpStreamConn) SetDeadline(time.Time) error      { return nil }
func (c *httpStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *httpStreamConn) SetWriteDeadline(time.Time) error { return nil }

type httpClientTarget struct {
	scheme     string
	urlHost    string
	headerHost string
}

func buildHTTPTransport(serverAddress string, tlsEnabled bool, hostOverride string, dialContext func(ctx context.Context, network, addr string) (net.Conn, error), maxIdleConns int) (*http.Transport, httpClientTarget, error) {
	if dialContext == nil {
		panic("httpmask: DialContext is nil")
	}

	scheme, urlHost, dialAddr, serverName, err := normalizeHTTPDialTarget(serverAddress, tlsEnabled, hostOverride)
	if err != nil {
		return nil, httpClientTarget{}, err
	}

	transport := &http.Transport{
		ForceAttemptHTTP2:     scheme == "https",
		DisableCompression:    true,
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConns,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return dialContext(dialCtx, network, dialAddr)
		},
	}
	if scheme == "https" {
		var tlsConf *tls.Config
		tlsConf, err = ca.GetTLSConfig(ca.Option{TLSConfig: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}})
		if err != nil {
			return nil, httpClientTarget{}, err
		}
		transport.TLSClientConfig = tlsConf
	}

	return transport, httpClientTarget{
		scheme:     scheme,
		urlHost:    urlHost,
		headerHost: canonicalHeaderHost(urlHost, scheme),
	}, nil
}

func newHTTPClient(serverAddress string, opts TunnelDialOptions, maxIdleConns int) (*http.Client, httpClientTarget, error) {
	transport, target, err := buildHTTPTransport(serverAddress, opts.TLSEnabled, opts.HostOverride, opts.DialContext, maxIdleConns)
	if err != nil {
		return nil, httpClientTarget{}, err
	}
	return &http.Client{Transport: transport}, target, nil
}

type sessionDialInfo struct {
	client     *http.Client
	pushURL    string
	pullURL    string
	closeURL   string
	headerHost string
	auth       *tunnelAuth
}

func dialSessionWithClient(ctx context.Context, client *http.Client, target httpClientTarget, mode TunnelMode, opts TunnelDialOptions) (*sessionDialInfo, error) {
	if client == nil {
		return nil, fmt.Errorf("nil http client")
	}

	auth := newTunnelAuth(opts.AuthKey, 0)
	authorizeURL := (&url.URL{Scheme: target.scheme, Host: target.urlHost, Path: joinPathRoot(opts.PathRoot, "/session")}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = target.headerHost
	applyTunnelHeaders(req.Header, target.headerHost, mode)
	applyTunnelAuthHeader(req.Header, auth, mode, http.MethodGet, "/session")

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
		return nil, fmt.Errorf("%s authorize bad status: %s (%s)", mode, resp.Status, strings.TrimSpace(string(bodyBytes)))
	}

	token, err := parseTunnelToken(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("%s authorize failed: %q", mode, strings.TrimSpace(string(bodyBytes)))
	}
	if token == "" {
		return nil, fmt.Errorf("%s authorize empty token", mode)
	}

	pushURL := (&url.URL{Scheme: target.scheme, Host: target.urlHost, Path: joinPathRoot(opts.PathRoot, "/api/v1/upload"), RawQuery: "token=" + url.QueryEscape(token)}).String()
	pullURL := (&url.URL{Scheme: target.scheme, Host: target.urlHost, Path: joinPathRoot(opts.PathRoot, "/stream"), RawQuery: "token=" + url.QueryEscape(token)}).String()
	closeURL := (&url.URL{Scheme: target.scheme, Host: target.urlHost, Path: joinPathRoot(opts.PathRoot, "/api/v1/upload"), RawQuery: "token=" + url.QueryEscape(token) + "&close=1"}).String()

	return &sessionDialInfo{
		client:     client,
		pushURL:    pushURL,
		pullURL:    pullURL,
		closeURL:   closeURL,
		headerHost: target.headerHost,
		auth:       auth,
	}, nil
}

func dialSession(ctx context.Context, serverAddress string, opts TunnelDialOptions, mode TunnelMode) (*sessionDialInfo, error) {
	client, target, err := newHTTPClient(serverAddress, opts, 32)
	if err != nil {
		return nil, err
	}
	return dialSessionWithClient(ctx, client, target, mode, opts)
}

func bestEffortCloseSession(client *http.Client, closeURL, headerHost string, mode TunnelMode, auth *tunnelAuth) {
	if client == nil || closeURL == "" || headerHost == "" {
		return
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(closeCtx, http.MethodPost, closeURL, nil)
	if err != nil {
		return
	}
	req.Host = headerHost
	applyTunnelHeaders(req.Header, headerHost, mode)
	applyTunnelAuthHeader(req.Header, auth, mode, http.MethodPost, "/api/v1/upload")

	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
	_ = resp.Body.Close()
}

func dialStreamWithClient(ctx context.Context, client *http.Client, target httpClientTarget, opts TunnelDialOptions) (net.Conn, error) {
	// Prefer split-session (Cloudflare-friendly). Fall back to stream-one for older servers / environments.
	c, errSplit := dialStreamSplitWithClient(ctx, client, target, opts)
	if errSplit == nil {
		return c, nil
	}
	c2, errOne := dialStreamOneWithClient(ctx, client, target, opts)
	if errOne == nil {
		return c2, nil
	}
	return nil, fmt.Errorf("dial stream failed: split: %v; stream-one: %w", errSplit, errOne)
}

func dialStream(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	// Prefer split-session (Cloudflare-friendly). Fall back to stream-one for older servers / environments.
	c, errSplit := dialStreamSplit(ctx, serverAddress, opts)
	if errSplit == nil {
		return c, nil
	}
	c2, errOne := dialStreamOne(ctx, serverAddress, opts)
	if errOne == nil {
		return c2, nil
	}
	return nil, fmt.Errorf("dial stream failed: split: %v; stream-one: %w", errSplit, errOne)
}

func dialStreamOneWithClient(ctx context.Context, client *http.Client, target httpClientTarget, opts TunnelDialOptions) (net.Conn, error) {
	if client == nil {
		return nil, fmt.Errorf("nil http client")
	}

	auth := newTunnelAuth(opts.AuthKey, 0)
	r := rngPool.Get().(*mrand.Rand)
	basePath := paths[r.Intn(len(paths))]
	path := joinPathRoot(opts.PathRoot, basePath)
	ctype := contentTypes[r.Intn(len(contentTypes))]
	rngPool.Put(r)

	u := url.URL{
		Scheme: target.scheme,
		Host:   target.urlHost,
		Path:   path,
	}

	reqBodyR, reqBodyW := io.Pipe()

	connCtx, connCancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(connCtx, http.MethodPost, u.String(), reqBodyR)
	if err != nil {
		connCancel()
		_ = reqBodyW.Close()
		return nil, err
	}
	req.Host = target.headerHost

	applyTunnelHeaders(req.Header, target.headerHost, TunnelModeStream)
	applyTunnelAuthHeader(req.Header, auth, TunnelModeStream, http.MethodPost, basePath)
	req.Header.Set("Content-Type", ctype)

	type doResult struct {
		resp *http.Response
		err  error
	}
	doCh := make(chan doResult, 1)
	go func() {
		resp, doErr := client.Do(req)
		doCh <- doResult{resp: resp, err: doErr}
	}()

	streamConn := &httpStreamConn{
		writer:     reqBodyW,
		cancel:     connCancel,
		localAddr:  &net.TCPAddr{},
		remoteAddr: &net.TCPAddr{},
	}

	type upgradeResult struct {
		conn net.Conn
		err  error
	}
	upgradeCh := make(chan upgradeResult, 1)
	if opts.Upgrade == nil {
		upgradeCh <- upgradeResult{conn: streamConn, err: nil}
	} else {
		go func() {
			upgradeConn, err := opts.Upgrade(streamConn)
			if err != nil {
				upgradeCh <- upgradeResult{conn: nil, err: err}
				return
			}
			if upgradeConn == nil {
				upgradeConn = streamConn
			}
			upgradeCh <- upgradeResult{conn: upgradeConn, err: nil}
		}()
	}

	var (
		outConn       net.Conn
		upgradeDone   bool
		responseReady bool
	)

	for !(upgradeDone && responseReady) {
		select {
		case <-ctx.Done():
			_ = streamConn.Close()
			if outConn != nil && outConn != streamConn {
				_ = outConn.Close()
			}
			return nil, ctx.Err()

		case u := <-upgradeCh:
			if u.err != nil {
				_ = streamConn.Close()
				return nil, u.err
			}
			outConn = u.conn
			if outConn == nil {
				outConn = streamConn
			}
			upgradeDone = true

		case r := <-doCh:
			if r.err != nil {
				_ = streamConn.Close()
				if outConn != nil && outConn != streamConn {
					_ = outConn.Close()
				}
				return nil, r.err
			}
			if r.resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(r.resp.Body, 4*1024))
				_ = r.resp.Body.Close()
				_ = streamConn.Close()
				if outConn != nil && outConn != streamConn {
					_ = outConn.Close()
				}
				return nil, fmt.Errorf("stream bad status: %s (%s)", r.resp.Status, strings.TrimSpace(string(body)))
			}

			streamConn.reader = r.resp.Body
			responseReady = true
		}
	}

	return outConn, nil
}

func dialStreamOne(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	client, target, err := newHTTPClient(serverAddress, opts, 32)
	if err != nil {
		return nil, err
	}
	return dialStreamOneWithClient(ctx, client, target, opts)
}

type queuedConn struct {
	rxc    chan []byte
	closed chan struct{}

	writeCh chan []byte

	mu         sync.Mutex
	readBuf    []byte
	closeErr   error
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *queuedConn) closeWithError(err error) error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil
	default:
		if err == nil {
			err = io.ErrClosedPipe
		}
		if c.closeErr == nil {
			c.closeErr = err
		}
		close(c.closed)
	}
	c.mu.Unlock()
	return nil
}

func (c *queuedConn) closedErr() error {
	c.mu.Lock()
	err := c.closeErr
	c.mu.Unlock()
	if err == nil {
		return io.ErrClosedPipe
	}
	return err
}

func (c *queuedConn) Read(b []byte) (n int, err error) {
	if len(c.readBuf) == 0 {
		select {
		case c.readBuf = <-c.rxc:
		case <-c.closed:
			return 0, c.closedErr()
		}
	}
	n = copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *queuedConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return 0, c.closedErr()
	default:
	}
	c.mu.Unlock()

	payload := make([]byte, len(b))
	copy(payload, b)
	select {
	case c.writeCh <- payload:
		return len(b), nil
	case <-c.closed:
		return 0, c.closedErr()
	}
}

func (c *queuedConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *queuedConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *queuedConn) SetDeadline(time.Time) error      { return nil }
func (c *queuedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *queuedConn) SetWriteDeadline(time.Time) error { return nil }

type streamSplitConn struct {
	queuedConn

	ctx    context.Context
	cancel context.CancelFunc

	client     *http.Client
	pushURL    string
	pullURL    string
	closeURL   string
	headerHost string
	auth       *tunnelAuth
}

func (c *streamSplitConn) Close() error {
	_ = c.closeWithError(io.ErrClosedPipe)

	if c.cancel != nil {
		c.cancel()
	}
	bestEffortCloseSession(c.client, c.closeURL, c.headerHost, TunnelModeStream, c.auth)
	return nil
}

func newStreamSplitConnFromInfo(info *sessionDialInfo) *streamSplitConn {
	if info == nil {
		return nil
	}

	connCtx, cancel := context.WithCancel(context.Background())
	c := &streamSplitConn{
		ctx:        connCtx,
		cancel:     cancel,
		client:     info.client,
		pushURL:    info.pushURL,
		pullURL:    info.pullURL,
		closeURL:   info.closeURL,
		headerHost: info.headerHost,
		auth:       info.auth,
		queuedConn: queuedConn{
			rxc:        make(chan []byte, 256),
			closed:     make(chan struct{}),
			writeCh:    make(chan []byte, 256),
			localAddr:  &net.TCPAddr{},
			remoteAddr: &net.TCPAddr{},
		},
	}

	go c.pullLoop()
	go c.pushLoop()
	return c
}

func dialStreamSplitWithClient(ctx context.Context, client *http.Client, target httpClientTarget, opts TunnelDialOptions) (net.Conn, error) {
	info, err := dialSessionWithClient(ctx, client, target, TunnelModeStream, opts)
	if err != nil {
		return nil, err
	}
	c := newStreamSplitConnFromInfo(info)
	if c == nil {
		return nil, fmt.Errorf("failed to build stream split conn")
	}
	outConn := net.Conn(c)
	if opts.Upgrade != nil {
		upgraded, err := opts.Upgrade(c)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if upgraded != nil {
			outConn = upgraded
		}
	}
	return outConn, nil
}

func dialStreamSplit(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	info, err := dialSession(ctx, serverAddress, opts, TunnelModeStream)
	if err != nil {
		return nil, err
	}
	c := newStreamSplitConnFromInfo(info)
	if c == nil {
		return nil, fmt.Errorf("failed to build stream split conn")
	}
	outConn := net.Conn(c)
	if opts.Upgrade != nil {
		upgraded, err := opts.Upgrade(c)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if upgraded != nil {
			outConn = upgraded
		}
	}
	return outConn, nil
}

func (c *streamSplitConn) pullLoop() {
	const (
		// requestTimeout must be long enough for continuous high-throughput streams (e.g. mux + large downloads).
		// If it is too short, the client cancels the response mid-body and corrupts the byte stream.
		requestTimeout = 2 * time.Minute
		readChunkSize  = 32 * 1024
		idleBackoff    = 25 * time.Millisecond
		maxDialRetry   = 12
		minBackoff     = 10 * time.Millisecond
		maxBackoff     = 250 * time.Millisecond
	)

	var (
		dialRetry int
		backoff   = minBackoff
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
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModeStream)
		applyTunnelAuthHeader(req.Header, c.auth, TunnelModeStream, http.MethodGet, "/stream")

		resp, err := c.client.Do(req)
		if err != nil {
			cancel()
			if isDialError(err) && dialRetry < maxDialRetry {
				dialRetry++
				select {
				case <-time.After(backoff):
				case <-c.closed:
					return
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			_ = c.Close()
			return
		}
		dialRetry = 0
		backoff = minBackoff

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
					cancel()
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

func (c *streamSplitConn) pushLoop() {
	const (
		maxBatchBytes  = 256 * 1024
		flushInterval  = 5 * time.Millisecond
		requestTimeout = 20 * time.Second
		maxDialRetry   = 12
		minBackoff     = 10 * time.Millisecond
		maxBackoff     = 250 * time.Millisecond
	)

	var (
		buf   bytes.Buffer
		timer = time.NewTimer(flushInterval)
	)
	defer timer.Stop()

	flush := func() error {
		if buf.Len() == 0 {
			return nil
		}

		reqCtx, cancel := context.WithTimeout(c.ctx, requestTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.pushURL, bytes.NewReader(buf.Bytes()))
		if err != nil {
			cancel()
			return err
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModeStream)
		applyTunnelAuthHeader(req.Header, c.auth, TunnelModeStream, http.MethodPost, "/api/v1/upload")
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := c.client.Do(req)
		if err != nil {
			cancel()
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("bad status: %s", resp.Status)
		}

		buf.Reset()
		return nil
	}

	flushWithRetry := func() error {
		dialRetry := 0
		backoff := minBackoff
		for {
			if err := flush(); err == nil {
				return nil
			} else if isDialError(err) && dialRetry < maxDialRetry {
				dialRetry++
				select {
				case <-time.After(backoff):
				case <-c.closed:
					return io.ErrClosedPipe
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			} else {
				return err
			}
		}
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
				_ = flushWithRetry()
				return
			}
			if len(b) == 0 {
				continue
			}
			if buf.Len()+len(b) > maxBatchBytes {
				if err := flushWithRetry(); err != nil {
					_ = c.Close()
					return
				}
				resetTimer()
			}
			_, _ = buf.Write(b)
			if buf.Len() >= maxBatchBytes {
				if err := flushWithRetry(); err != nil {
					_ = c.Close()
					return
				}
				resetTimer()
			}
		case <-timer.C:
			if err := flushWithRetry(); err != nil {
				_ = c.Close()
				return
			}
			resetTimer()
		case <-c.closed:
			_ = flushWithRetry()
			return
		}
	}
}

type pollConn struct {
	queuedConn

	ctx    context.Context
	cancel context.CancelFunc

	client     *http.Client
	pushURL    string
	pullURL    string
	closeURL   string
	headerHost string
	auth       *tunnelAuth
}

func isDialError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return isDialError(urlErr.Err)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" || opErr.Op == "connect" {
			return true
		}
	}
	return false
}

func (c *pollConn) closeWithError(err error) error {
	_ = c.queuedConn.closeWithError(err)
	if c.cancel != nil {
		c.cancel()
	}
	bestEffortCloseSession(c.client, c.closeURL, c.headerHost, TunnelModePoll, c.auth)
	return nil
}

func (c *pollConn) Close() error {
	return c.closeWithError(io.ErrClosedPipe)
}

func newPollConnFromInfo(info *sessionDialInfo) *pollConn {
	if info == nil {
		return nil
	}

	connCtx, cancel := context.WithCancel(context.Background())
	c := &pollConn{
		ctx:        connCtx,
		cancel:     cancel,
		client:     info.client,
		pushURL:    info.pushURL,
		pullURL:    info.pullURL,
		closeURL:   info.closeURL,
		headerHost: info.headerHost,
		auth:       info.auth,
		queuedConn: queuedConn{
			rxc:        make(chan []byte, 128),
			closed:     make(chan struct{}),
			writeCh:    make(chan []byte, 256),
			localAddr:  &net.TCPAddr{},
			remoteAddr: &net.TCPAddr{},
		},
	}

	go c.pullLoop()
	go c.pushLoop()
	return c
}

func dialPollWithClient(ctx context.Context, client *http.Client, target httpClientTarget, opts TunnelDialOptions) (net.Conn, error) {
	info, err := dialSessionWithClient(ctx, client, target, TunnelModePoll, opts)
	if err != nil {
		return nil, err
	}
	c := newPollConnFromInfo(info)
	if c == nil {
		return nil, fmt.Errorf("failed to build poll conn")
	}
	outConn := net.Conn(c)
	if opts.Upgrade != nil {
		upgraded, err := opts.Upgrade(c)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if upgraded != nil {
			outConn = upgraded
		}
	}
	return outConn, nil
}

func dialPoll(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	info, err := dialSession(ctx, serverAddress, opts, TunnelModePoll)
	if err != nil {
		return nil, err
	}
	c := newPollConnFromInfo(info)
	if c == nil {
		return nil, fmt.Errorf("failed to build poll conn")
	}
	outConn := net.Conn(c)
	if opts.Upgrade != nil {
		upgraded, err := opts.Upgrade(c)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if upgraded != nil {
			outConn = upgraded
		}
	}
	return outConn, nil
}

func (c *pollConn) pullLoop() {
	const (
		maxDialRetry = 12
		minBackoff   = 10 * time.Millisecond
		maxBackoff   = 250 * time.Millisecond
	)
	var (
		dialRetry int
		backoff   = minBackoff
	)
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
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModePoll)
		applyTunnelAuthHeader(req.Header, c.auth, TunnelModePoll, http.MethodGet, "/stream")

		resp, err := c.client.Do(req)
		if err != nil {
			if isDialError(err) && dialRetry < maxDialRetry {
				dialRetry++
				select {
				case <-time.After(backoff):
				case <-c.closed:
					return
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			_ = c.closeWithError(fmt.Errorf("poll pull request failed: %w", err))
			return
		}
		dialRetry = 0
		backoff = minBackoff

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			_ = c.closeWithError(fmt.Errorf("poll pull bad status: %s", resp.Status))
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
				_ = c.closeWithError(fmt.Errorf("poll pull decode failed: %w", err))
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
			_ = c.closeWithError(fmt.Errorf("poll pull scan failed: %w", err))
			return
		}
	}
}

func (c *pollConn) pushLoop() {
	const (
		maxBatchBytes   = 64 * 1024
		flushInterval   = 5 * time.Millisecond
		maxLineRawBytes = 16 * 1024
		maxDialRetry    = 12
		minBackoff      = 10 * time.Millisecond
		maxBackoff      = 250 * time.Millisecond
	)

	var (
		buf        bytes.Buffer
		pendingRaw int
		timer      = time.NewTimer(flushInterval)
	)
	defer timer.Stop()

	flush := func() error {
		if buf.Len() == 0 {
			return nil
		}

		req, err := http.NewRequest(http.MethodPost, c.pushURL, bytes.NewReader(buf.Bytes()))
		if err != nil {
			return err
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModePoll)
		applyTunnelAuthHeader(req.Header, c.auth, TunnelModePoll, http.MethodPost, "/api/v1/upload")
		req.Header.Set("Content-Type", "text/plain")

		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("bad status: %s", resp.Status)
		}

		buf.Reset()
		pendingRaw = 0
		return nil
	}

	flushWithRetry := func() error {
		dialRetry := 0
		backoff := minBackoff
		for {
			if err := flush(); err == nil {
				return nil
			} else if isDialError(err) && dialRetry < maxDialRetry {
				dialRetry++
				select {
				case <-time.After(backoff):
				case <-c.closed:
					return c.closedErr()
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			} else {
				return err
			}
		}
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
				_ = flushWithRetry()
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
					if err := flushWithRetry(); err != nil {
						_ = c.closeWithError(fmt.Errorf("poll push flush failed: %w", err))
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
				if err := flushWithRetry(); err != nil {
					_ = c.closeWithError(fmt.Errorf("poll push flush failed: %w", err))
					return
				}
				resetTimer()
			}
		case <-timer.C:
			if err := flushWithRetry(); err != nil {
				_ = c.closeWithError(fmt.Errorf("poll push flush failed: %w", err))
				return
			}
			resetTimer()
		case <-c.closed:
			_ = flushWithRetry()
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

	if tlsEnabled {
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
	// PathRoot is an optional first-level path prefix for all HTTP tunnel endpoints.
	// Example: "aabbcc" => "/aabbcc/session", "/aabbcc/api/v1/upload", ...
	PathRoot string
	// AuthKey enables short-term HMAC auth for HTTP tunnel requests (anti-probing).
	// When set (non-empty), the server requires each request to carry a valid Authorization bearer token.
	AuthKey string
	// AuthSkew controls allowed clock skew / replay window for AuthKey. 0 uses a conservative default.
	AuthSkew time.Duration
	// PassThroughOnReject controls how the server handles "recognized but rejected" tunnel requests
	// (e.g., wrong mode / wrong path / invalid token). When true, the request bytes are replayed back
	// to the caller as HandlePassThrough to allow higher-level fallback handling.
	PassThroughOnReject bool
	// PullReadTimeout controls how long the server long-poll waits for tunnel downlink data before replying with a keepalive newline.
	PullReadTimeout time.Duration
	// SessionTTL is a best-effort TTL to prevent leaked sessions. 0 uses a conservative default.
	SessionTTL time.Duration
}

type TunnelServer struct {
	mode                TunnelMode
	pathRoot            string
	passThroughOnReject bool
	auth                *tunnelAuth

	pullReadTimeout time.Duration
	sessionTTL      time.Duration

	mu       sync.Mutex
	sessions map[string]*tunnelSession
}

type tunnelSession struct {
	conn       net.Conn
	lastActive time.Time
}

func NewTunnelServer(opts TunnelServerOptions) *TunnelServer {
	mode := normalizeTunnelMode(opts.Mode)
	if mode == TunnelModeLegacy {
		// Server-side "legacy" means: don't accept stream/poll tunnels; only passthrough.
	}
	pathRoot := normalizePathRoot(opts.PathRoot)
	auth := newTunnelAuth(opts.AuthKey, opts.AuthSkew)
	timeout := opts.PullReadTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ttl := opts.SessionTTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &TunnelServer{
		mode:                mode,
		pathRoot:            pathRoot,
		auth:                auth,
		passThroughOnReject: opts.PassThroughOnReject,
		pullReadTimeout:     timeout,
		sessionTTL:          ttl,
		sessions:            make(map[string]*tunnelSession),
	}
}

// HandleConn inspects rawConn. If it is an HTTP tunnel request (X-Sudoku-Tunnel header), it is handled here and:
//   - returns HandleStartTunnel + a net.Conn that carries the raw Sudoku stream (stream mode or poll session pipe)
//   - or returns HandleDone if the HTTP request is a poll control request (push/pull) and no Sudoku handshake should run on this TCP conn
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
		if s.passThroughOnReject {
			prefix := make([]byte, 0, len(headerBytes)+len(buffered))
			prefix = append(prefix, headerBytes...)
			prefix = append(prefix, buffered...)
			return HandlePassThrough, newPreBufferedConn(rawConn, prefix), nil
		}
		_ = writeSimpleHTTPResponse(rawConn, http.StatusNotFound, "not found")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	switch TunnelMode(tunnelHeader) {
	case TunnelModeStream:
		if s.mode != TunnelModeStream && s.mode != TunnelModeAuto {
			if s.passThroughOnReject {
				prefix := make([]byte, 0, len(headerBytes)+len(buffered))
				prefix = append(prefix, headerBytes...)
				prefix = append(prefix, buffered...)
				return HandlePassThrough, newPreBufferedConn(rawConn, prefix), nil
			}
			_ = writeSimpleHTTPResponse(rawConn, http.StatusNotFound, "not found")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
		return s.handleStream(rawConn, req, headerBytes, buffered)
	case TunnelModePoll:
		if s.mode != TunnelModePoll && s.mode != TunnelModeAuto {
			if s.passThroughOnReject {
				prefix := make([]byte, 0, len(headerBytes)+len(buffered))
				prefix = append(prefix, headerBytes...)
				prefix = append(prefix, buffered...)
				return HandlePassThrough, newPreBufferedConn(rawConn, prefix), nil
			}
			_ = writeSimpleHTTPResponse(rawConn, http.StatusNotFound, "not found")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
		return s.handlePoll(rawConn, req, headerBytes, buffered)
	default:
		if s.passThroughOnReject {
			prefix := make([]byte, 0, len(headerBytes)+len(buffered))
			prefix = append(prefix, headerBytes...)
			prefix = append(prefix, buffered...)
			return HandlePassThrough, newPreBufferedConn(rawConn, prefix), nil
		}
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

func (s *TunnelServer) handleStream(rawConn net.Conn, req *httpRequestHeader, headerBytes []byte, buffered []byte) (HandleResult, net.Conn, error) {
	rejectOrReply := func(code int, body string) (HandleResult, net.Conn, error) {
		if s.passThroughOnReject {
			prefix := make([]byte, 0, len(headerBytes)+len(buffered))
			prefix = append(prefix, headerBytes...)
			prefix = append(prefix, buffered...)
			return HandlePassThrough, newPreBufferedConn(rawConn, prefix), nil
		}
		_ = writeSimpleHTTPResponse(rawConn, code, body)
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	u, err := url.ParseRequestURI(req.target)
	if err != nil {
		return rejectOrReply(http.StatusBadRequest, "bad request")
	}

	// Only accept plausible paths to reduce accidental exposure.
	path, ok := stripPathRoot(s.pathRoot, u.Path)
	if !ok || !s.isAllowedBasePath(path) {
		return rejectOrReply(http.StatusNotFound, "not found")
	}
	if !s.auth.verify(req.headers, TunnelModeStream, req.method, path, time.Now()) {
		return rejectOrReply(http.StatusNotFound, "not found")
	}

	token := u.Query().Get("token")
	closeFlag := u.Query().Get("close") == "1"

	switch strings.ToUpper(req.method) {
	case http.MethodGet:
		// Stream split-session: GET /session (no token) => token + start tunnel on a server-side pipe.
		if token == "" && path == "/session" {
			return s.authorizeSession(rawConn)
		}
		// Stream split-session: GET /stream?token=... => downlink poll.
		if token != "" && path == "/stream" {
			return s.streamPull(rawConn, token)
		}
		return rejectOrReply(http.StatusBadRequest, "bad request")

	case http.MethodPost:
		// Stream split-session: POST /api/v1/upload?token=... => uplink push.
		if token != "" && path == "/api/v1/upload" {
			if closeFlag {
				s.closeSession(token)
				return rejectOrReply(http.StatusOK, "")
			}
			bodyReader, err := newRequestBodyReader(newPreBufferedConn(rawConn, buffered), req.headers)
			if err != nil {
				return rejectOrReply(http.StatusBadRequest, "bad request")
			}
			return s.streamPush(rawConn, token, bodyReader)
		}

		// Stream-one: single full-duplex POST.
		if err := writeTunnelResponseHeader(rawConn); err != nil {
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
		return rejectOrReply(http.StatusBadRequest, "bad request")
	}
}

func (s *TunnelServer) isAllowedBasePath(path string) bool {
	for _, p := range paths {
		if path == p {
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

func writeTunnelResponseHeader(w io.Writer) error {
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

func (s *TunnelServer) handlePoll(rawConn net.Conn, req *httpRequestHeader, headerBytes []byte, buffered []byte) (HandleResult, net.Conn, error) {
	rejectOrReply := func(code int, body string) (HandleResult, net.Conn, error) {
		if s.passThroughOnReject {
			prefix := make([]byte, 0, len(headerBytes)+len(buffered))
			prefix = append(prefix, headerBytes...)
			prefix = append(prefix, buffered...)
			return HandlePassThrough, newPreBufferedConn(rawConn, prefix), nil
		}
		_ = writeSimpleHTTPResponse(rawConn, code, body)
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	u, err := url.ParseRequestURI(req.target)
	if err != nil {
		return rejectOrReply(http.StatusBadRequest, "bad request")
	}

	path, ok := stripPathRoot(s.pathRoot, u.Path)
	if !ok || !s.isAllowedBasePath(path) {
		return rejectOrReply(http.StatusNotFound, "not found")
	}
	if !s.auth.verify(req.headers, TunnelModePoll, req.method, path, time.Now()) {
		return rejectOrReply(http.StatusNotFound, "not found")
	}

	token := u.Query().Get("token")
	closeFlag := u.Query().Get("close") == "1"
	switch strings.ToUpper(req.method) {
	case http.MethodGet:
		if token == "" && path == "/session" {
			return s.authorizeSession(rawConn)
		}
		if token != "" && path == "/stream" {
			return s.pollPull(rawConn, token)
		}
		return rejectOrReply(http.StatusBadRequest, "bad request")
	case http.MethodPost:
		if token == "" || path != "/api/v1/upload" {
			return rejectOrReply(http.StatusBadRequest, "bad request")
		}
		if closeFlag {
			s.closeSession(token)
			return rejectOrReply(http.StatusOK, "")
		}
		bodyReader, err := newRequestBodyReader(newPreBufferedConn(rawConn, buffered), req.headers)
		if err != nil {
			return rejectOrReply(http.StatusBadRequest, "bad request")
		}
		return s.pollPush(rawConn, token, bodyReader)
	default:
		return rejectOrReply(http.StatusBadRequest, "bad request")
	}
}

func (s *TunnelServer) authorizeSession(rawConn net.Conn) (HandleResult, net.Conn, error) {
	token, err := newSessionToken()
	if err != nil {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusInternalServerError, "internal error")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	c1, c2 := net.Pipe()

	s.mu.Lock()
	s.sessions[token] = &tunnelSession{conn: c2, lastActive: time.Now()}
	s.mu.Unlock()

	go s.reapSessionLater(token)

	_ = writeTokenHTTPResponse(rawConn, token)
	_ = rawConn.Close()
	return HandleStartTunnel, c1, nil
}

func newSessionToken() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (s *TunnelServer) reapSessionLater(token string) {
	ttl := s.sessionTTL
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

func (s *TunnelServer) getSession(token string) (*tunnelSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	sess.lastActive = time.Now()
	return sess, true
}

func (s *TunnelServer) closeSession(token string) {
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

func (s *TunnelServer) pollPush(rawConn net.Conn, token string, body io.Reader) (HandleResult, net.Conn, error) {
	sess, ok := s.getSession(token)
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
			s.closeSession(token)
			_ = writeSimpleHTTPResponse(rawConn, http.StatusGone, "gone")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
	}

	_ = writeSimpleHTTPResponse(rawConn, http.StatusOK, "")
	_ = rawConn.Close()
	return HandleDone, nil, nil
}

func (s *TunnelServer) streamPush(rawConn net.Conn, token string, body io.Reader) (HandleResult, net.Conn, error) {
	sess, ok := s.getSession(token)
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
			s.closeSession(token)
			_ = writeSimpleHTTPResponse(rawConn, http.StatusGone, "gone")
			_ = rawConn.Close()
			return HandleDone, nil, nil
		}
	}

	_ = writeSimpleHTTPResponse(rawConn, http.StatusOK, "")
	_ = rawConn.Close()
	return HandleDone, nil, nil
}

func (s *TunnelServer) streamPull(rawConn net.Conn, token string) (HandleResult, net.Conn, error) {
	sess, ok := s.getSession(token)
	if !ok {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusForbidden, "forbidden")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	// Streaming response (chunked) with raw bytes (no base64 framing).
	if err := writeTunnelResponseHeader(rawConn); err != nil {
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
		_ = sess.conn.SetReadDeadline(time.Now().Add(s.pullReadTimeout))
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
			s.closeSession(token)
			return HandleDone, nil, nil
		}
	}
}

func (s *TunnelServer) pollPull(rawConn net.Conn, token string) (HandleResult, net.Conn, error) {
	sess, ok := s.getSession(token)
	if !ok {
		_ = writeSimpleHTTPResponse(rawConn, http.StatusForbidden, "forbidden")
		_ = rawConn.Close()
		return HandleDone, nil, nil
	}

	// Streaming response (chunked) with base64 lines.
	if err := writeTunnelResponseHeader(rawConn); err != nil {
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
		_ = sess.conn.SetReadDeadline(time.Now().Add(s.pullReadTimeout))
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
			s.closeSession(token)
			return HandleDone, nil, nil
		}
	}
}
