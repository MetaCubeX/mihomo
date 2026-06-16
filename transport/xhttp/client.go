package xhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

// ConnIdleTimeout defines the maximum time an idle TCP session can survive in the tunnel,
// so it should be consistent across HTTP versions and with other transports.
const ConnIdleTimeout = 300 * time.Second

// QuicgoH3KeepAlivePeriod consistent with quic-go
const QuicgoH3KeepAlivePeriod = 10 * time.Second

// ChromeH2KeepAlivePeriod consistent with chrome
const ChromeH2KeepAlivePeriod = 45 * time.Second

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)
type DialQUICFunc func(ctx context.Context, cfg *quic.Config) (*quic.Conn, error)

type TransportMaker func() http.RoundTripper

type PacketUpWriter struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	cfg                  *Config
	scMaxEachPostBytes   int
	scMinPostsIntervalMs Range
	sessionID            string
	transport            http.RoundTripper
	writeMu              sync.Mutex
	writeCond            sync.Cond
	seq                  uint64
	buf                  []byte
	timer                *time.Timer
	flushErr             error
}

func (c *PacketUpWriter) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.flushErr; err != nil {
		return 0, err
	}

	data := bytes.NewBuffer(b)
	for data.Len() > 0 {
		if c.timer == nil { // start a timer to flush the buffer
			c.timer = time.AfterFunc(time.Duration(c.scMinPostsIntervalMs.Rand())*time.Millisecond, c.flush)
		}

		c.buf = append(c.buf, data.Next(c.scMaxEachPostBytes-len(c.buf))...) // let buffer fill up to scMaxEachPostBytes

		if len(c.buf) >= c.scMaxEachPostBytes { // too much data in buffer, wait the flush complete
			c.writeCond.Wait()
			if err := c.flushErr; err != nil {
				return 0, err
			}
		}
	}
	return len(b), nil
}

func (c *PacketUpWriter) flush() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	defer c.writeCond.Broadcast() // wake up the waited Write() call

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}

	if c.flushErr != nil {
		return
	}

	if len(c.buf) == 0 {
		return
	}
	_, err := c.write(c.buf)
	c.buf = c.buf[:0] // reset buffer
	if err != nil {
		c.flushErr = err
		return
	}
}

func (c *PacketUpWriter) write(b []byte) (int, error) {
	u := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}

	req, err := http.NewRequestWithContext(c.ctx, c.cfg.GetNormalizedUplinkHTTPMethod(), u.String(), nil)
	if err != nil {
		return 0, err
	}

	seqStr := strconv.FormatUint(c.seq, 10)
	c.seq++

	if err := c.cfg.FillPacketRequest(req, c.sessionID, seqStr, b); err != nil {
		return 0, err
	}
	req.Host = c.cfg.Host

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}

	return len(b), nil
}

func (c *PacketUpWriter) Close() error {
	ch := make(chan struct{})
	go func() { // flush in the background
		defer close(ch)
		c.flush()
	}()
	select {
	case <-ch:
	case <-time.After(time.Second):
	}
	c.cancel()
	httputils.CloseTransport(c.transport)
	return nil
}

func NewTransport(dialRaw DialRawFunc, wrapTLS WrapTLSFunc, dialQUIC DialQUICFunc, alpn []string, keepAlivePeriod time.Duration) http.RoundTripper {
	if len(alpn) == 1 && alpn[0] == "h3" { // `alpn: [h3]` means using h3 mode
		if keepAlivePeriod == 0 {
			keepAlivePeriod = QuicgoH3KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		return &http3.Transport{
			QUICConfig: &quic.Config{
				MaxIncomingStreams: -1, // don't allow the server to create bidirectional streams
				KeepAlivePeriod:    keepAlivePeriod,
				MaxIdleTimeout:     ConnIdleTimeout,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return dialQUIC(ctx, cfg)
			},
		}
	}
	if len(alpn) == 1 && alpn[0] == "http/1.1" { // `alpn: [http/1.1]` means using http/1.1 mode
		dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dialRaw(ctx)
			if err != nil {
				return nil, err
			}
			wrapped, err := wrapTLS(ctx, raw, false)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return wrapped, nil
		}
		return &http.Transport{
			DialContext:       dialContext,
			DialTLSContext:    dialContext,
			IdleConnTimeout:   ConnIdleTimeout,
			ForceAttemptHTTP2: false, // only http/1.1
		}
	}
	if keepAlivePeriod == 0 {
		keepAlivePeriod = ChromeH2KeepAlivePeriod
	}
	if keepAlivePeriod < 0 {
		keepAlivePeriod = 0
	}
	// use h2c mode to disallow the net/http fallback to http1.1
	//
	// Note that this usage is only applicable to our own net/http fork.
	// The standard library also needs to mask the tls.Conn type for the conn returned by DialTLSContext,
	// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dialRaw(ctx)
			if err != nil {
				return nil, err
			}
			wrapped, err := wrapTLS(ctx, raw, true)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return wrapped, nil
		},
		IdleConnTimeout: ConnIdleTimeout,
		Protocols:       protocols,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: keepAlivePeriod,
		},
	}
}

type Client struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	mode                  string
	cfg                   *Config
	scMaxEachPostBytes    Range
	scMinPostsIntervalMs  Range
	generateSessionID     func() string
	makeTransport         TransportMaker
	makeDownloadTransport TransportMaker
	uploadManager         *ReuseManager
	downloadManager       *ReuseManager
}

func NewClient(cfg *Config, makeTransport TransportMaker, makeDownloadTransport TransportMaker, hasReality bool) (*Client, error) {
	mode := cfg.EffectiveMode(hasReality)
	switch mode {
	case "stream-one", "stream-up", "packet-up":
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", mode)
	}
	scMaxEachPostBytes, err := cfg.GetNormalizedScMaxEachPostBytes()
	if err != nil {
		return nil, err
	}
	scMinPostsIntervalMs, err := cfg.GetNormalizedScMinPostsIntervalMs()
	if err != nil {
		return nil, err
	}
	generateSessionID, err := cfg.GetGenerateSessionID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		mode:                  mode,
		cfg:                   cfg,
		scMaxEachPostBytes:    scMaxEachPostBytes,
		scMinPostsIntervalMs:  scMinPostsIntervalMs,
		generateSessionID:     generateSessionID,
		makeTransport:         makeTransport,
		makeDownloadTransport: makeDownloadTransport,
		ctx:                   ctx,
		cancel:                cancel,
	}
	if cfg.ReuseConfig != nil {
		client.uploadManager, err = NewReuseManager(cfg.ReuseConfig, makeTransport)
		if err != nil {
			return nil, err
		}
		client.makeTransport = client.uploadManager.GetTransport
		if cfg.DownloadConfig != nil {
			if makeDownloadTransport == nil {
				return nil, fmt.Errorf("xhttp: download manager requires download transport maker")
			}
			client.downloadManager, err = NewReuseManager(cfg.DownloadConfig.ReuseConfig, makeDownloadTransport)
			if err != nil {
				return nil, err
			}
			client.makeDownloadTransport = client.downloadManager.GetTransport
		}
	}
	return client, nil
}

func (c *Client) Close() error {
	c.cancel()
	var errs []error
	if c.uploadManager != nil {
		err := c.uploadManager.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if c.downloadManager != nil {
		err := c.downloadManager.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	switch c.mode {
	case "stream-one":
		return c.DialStreamOne(ctx)
	case "stream-up":
		return c.DialStreamUp(ctx)
	case "packet-up":
		return c.DialPacketUp(ctx)
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", c.mode)
	}
}

// onlyRoundTripper is a wrapper that prevents the underlying transport from being closed.
type onlyRoundTripper struct {
	http.RoundTripper
}

func (c *Client) getTransport() (uploadTransport http.RoundTripper, downloadTransport http.RoundTripper, err error) {
	uploadTransport = c.makeTransport()
	downloadTransport = onlyRoundTripper{uploadTransport}
	if c.makeDownloadTransport != nil {
		downloadTransport = c.makeDownloadTransport()
	}
	return
}

func (c *Client) DialStreamOne(ctx context.Context) (net.Conn, error) {
	transport, _, err := c.getTransport()
	if err != nil {
		return nil, err
	}

	requestURL := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()

	conn := &Conn{writer: pw}

	// Use gotConn to detect when TCP connection is established, so we can
	// return the conn immediately without waiting for the HTTP response.
	// This breaks the deadlock where CDN buffers response headers until the
	// server sends body data, but the server waits for our request body,
	// which can't be sent because we haven't returned the conn yet.
	gotConn := make(chan bool, 1)

	reqCtx, reqCancel := context.WithCancel(c.ctx) // reqCtx must alive during conn not closed
	stop := contextutils.AfterFunc(ctx, reqCancel) // temporarily connect ctx with reqCtx when dialing
	defer stop()                                   // disconnect ctx with reqCtx after dialing

	addrCtx := httputils.NewAddrContext(&conn.NetAddr, reqCtx)
	streamCtx := httptrace.WithClientTrace(addrCtx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			select {
			case gotConn <- true:
			default: // GotConn maybe called multiple times, ignore the second and later calls
			}
		},
	})

	req, err := http.NewRequestWithContext(streamCtx, c.cfg.GetNormalizedUplinkHTTPMethod(), requestURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		reqCancel()
		return nil, err
	}
	req.Host = c.cfg.Host

	if err = c.cfg.FillStreamRequest(req, ""); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		reqCancel()
		return nil, err
	}

	wrc := NewWaitReadCloser()

	go func() {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			wrc.CloseWithError(err)
			close(gotConn)
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			wrc.CloseWithError(fmt.Errorf("xhttp stream-one bad status: %s", resp.Status))
			return
		}
		wrc.Set(resp.Body)
	}()

	if !<-gotConn {
		// RoundTrip failed before TCP connected (e.g. DNS failure)
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		reqCancel()
		var buf [0]byte
		_, err = wrc.Read(buf[:])
		return nil, err
	}

	conn.reader = wrc
	conn.onClose = func() {
		_ = pr.Close()
		httputils.CloseTransport(transport)
		reqCancel()
	}

	return conn, nil
}

func (c *Client) DialStreamUp(ctx context.Context) (net.Conn, error) {
	uploadTransport, downloadTransport, err := c.getTransport()
	if err != nil {
		return nil, err
	}

	downloadCfg := c.cfg
	if ds := c.cfg.DownloadConfig; ds != nil {
		downloadCfg = ds
	}

	streamURL := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()

	conn := &Conn{writer: pw}

	sessionID := c.generateSessionID()

	// Async download: avoid blocking on CDN response header buffering
	gotConn := make(chan bool, 1)

	reqCtx, reqCancel := context.WithCancel(c.ctx) // reqCtx must alive during conn not closed
	stop := contextutils.AfterFunc(ctx, reqCancel) // temporarily connect ctx with reqCtx when dialing
	defer stop()                                   // disconnect ctx with reqCtx after dialing

	addrCtx := httputils.NewAddrContext(&conn.NetAddr, reqCtx)
	downloadCtx := httptrace.WithClientTrace(addrCtx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			select {
			case gotConn <- true:
			default: // GotConn maybe called multiple times, ignore the second and later calls
			}
		},
	})

	downloadReq, err := http.NewRequestWithContext(
		downloadCtx,
		http.MethodGet,
		downloadURL.String(),
		nil,
	)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		reqCancel()
		return nil, err
	}

	if err := downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		reqCancel()
		return nil, err
	}
	downloadReq.Host = downloadCfg.Host

	uploadReq, err := http.NewRequestWithContext(
		reqCtx,
		c.cfg.GetNormalizedUplinkHTTPMethod(),
		streamURL.String(),
		pr,
	)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		reqCancel()
		return nil, err
	}

	if err = c.cfg.FillStreamRequest(uploadReq, sessionID); err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		reqCancel()
		return nil, err
	}
	uploadReq.Host = c.cfg.Host

	wrc := NewWaitReadCloser()

	go func() {
		resp, err := downloadTransport.RoundTrip(downloadReq)
		if err != nil {
			wrc.CloseWithError(err)
			close(gotConn)
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			wrc.CloseWithError(fmt.Errorf("xhttp stream-up download bad status: %s", resp.Status))
			return
		}
		wrc.Set(resp.Body)
	}()

	if !<-gotConn {
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		reqCancel()
		var buf [0]byte
		_, err = wrc.Read(buf[:])
		return nil, err
	}

	// Start upload after download TCP is connected, so the server has likely
	// already processed the GET and created the session. This preserves the
	// original ordering (download before upload) while still being async.
	go func() {
		resp, err := uploadTransport.RoundTrip(uploadReq)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = pw.CloseWithError(fmt.Errorf("xhttp stream-up upload bad status: %s", resp.Status))
		}
	}()

	conn.reader = wrc
	conn.onClose = func() {
		_ = pr.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		reqCancel()
	}

	return conn, nil
}

func (c *Client) DialPacketUp(ctx context.Context) (net.Conn, error) {
	uploadTransport, downloadTransport, err := c.getTransport()
	if err != nil {
		return nil, err
	}

	downloadCfg := c.cfg
	if ds := c.cfg.DownloadConfig; ds != nil {
		downloadCfg = ds
	}
	sessionID := c.generateSessionID()

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}

	writerCtx, writerCancel := context.WithCancel(c.ctx)
	writer := &PacketUpWriter{
		ctx:                  writerCtx,
		cancel:               writerCancel,
		cfg:                  c.cfg,
		scMaxEachPostBytes:   c.scMaxEachPostBytes.Rand(),
		scMinPostsIntervalMs: c.scMinPostsIntervalMs,
		sessionID:            sessionID,
		transport:            uploadTransport,
		seq:                  0,
	}
	writer.writeCond = sync.Cond{L: &writer.writeMu}
	conn := &Conn{writer: writer}

	// Async download: avoid blocking on CDN response header buffering
	gotConn := make(chan bool, 1)

	reqCtx, reqCancel := context.WithCancel(c.ctx) // reqCtx must alive during conn not closed
	stop := contextutils.AfterFunc(ctx, reqCancel) // temporarily connect ctx with reqCtx when dialing
	defer stop()                                   // disconnect ctx with reqCtx after dialing

	addrCtx := httputils.NewAddrContext(&conn.NetAddr, reqCtx)
	downloadCtx := httptrace.WithClientTrace(addrCtx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			select {
			case gotConn <- true:
			default: // GotConn maybe called multiple times, ignore the second and later calls
			}
		},
	})

	downloadReq, err := http.NewRequestWithContext(
		downloadCtx,
		http.MethodGet,
		downloadURL.String(),
		nil,
	)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		reqCancel()
		return nil, err
	}
	if err = downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		reqCancel()
		return nil, err
	}
	downloadReq.Host = downloadCfg.Host

	wrc := NewWaitReadCloser()

	go func() {
		resp, err := downloadTransport.RoundTrip(downloadReq)
		if err != nil {
			wrc.CloseWithError(err)
			close(gotConn)
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			wrc.CloseWithError(fmt.Errorf("xhttp packet-up download bad status: %s", resp.Status))
			return
		}
		wrc.Set(resp.Body)
	}()

	if !<-gotConn {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		reqCancel()
		var buf [0]byte
		_, err = wrc.Read(buf[:])
		return nil, err
	}

	conn.reader = wrc
	conn.onClose = func() {
		// uploadTransport already closed by writer
		httputils.CloseTransport(downloadTransport)
		reqCancel()
	}

	return conn, nil
}

// WaitReadCloser is an io.ReadCloser that blocks on Read() until the underlying
// ReadCloser is provided via Set(). This enables returning a reader immediately
// while the actual HTTP response body is obtained asynchronously in a goroutine,
// breaking the synchronous RoundTrip deadlock with CDN header buffering.
type WaitReadCloser struct {
	wait chan struct{}
	once sync.Once
	rc   io.ReadCloser
	err  error
}

func NewWaitReadCloser() *WaitReadCloser {
	return &WaitReadCloser{wait: make(chan struct{})}
}

// Set provides the underlying ReadCloser and unblocks any pending Read calls.
// Must be called at most once. If Close was already called, rc is closed to
// prevent leaks.
func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.setup(rc, nil)
}

// CloseWithError records an error and unblocks any pending Read calls.
func (w *WaitReadCloser) CloseWithError(err error) {
	w.setup(nil, err)
}

// setup sets the underlying ReadCloser and error.
func (w *WaitReadCloser) setup(rc io.ReadCloser, err error) {
	w.once.Do(func() {
		w.rc = rc
		w.err = err
		close(w.wait)
	})
	if w.err != nil && rc != nil {
		_ = rc.Close()
	}
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	<-w.wait
	if w.rc == nil {
		return 0, w.err
	}
	return w.rc.Read(b)
}

func (w *WaitReadCloser) Close() error {
	w.setup(nil, net.ErrClosed)
	<-w.wait
	if w.rc != nil {
		return w.rc.Close()
	}
	return nil
}
