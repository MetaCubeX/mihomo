package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"golang.org/x/sync/semaphore"
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

	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, u.String(), nil)
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
		w := semaphore.NewWeighted(20) // limit concurrent dialing to avoid WSAECONNREFUSED on Windows
		dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
			if err := w.Acquire(ctx, 1); err != nil {
				return nil, err
			}
			defer w.Release(1)
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
	return &http.Http2Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
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
		ReadIdleTimeout: keepAlivePeriod,
	}
}

type Client struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	mode                  string
	cfg                   *Config
	scMaxEachPostBytes    Range
	scMinPostsIntervalMs  Range
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
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		mode:                  mode,
		cfg:                   cfg,
		scMaxEachPostBytes:    scMaxEachPostBytes,
		scMinPostsIntervalMs:  scMinPostsIntervalMs,
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

func (c *Client) Dial() (net.Conn, error) {
	switch c.mode {
	case "stream-one":
		return c.DialStreamOne()
	case "stream-up":
		return c.DialStreamUp()
	case "packet-up":
		return c.DialPacketUp()
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

func (c *Client) DialStreamOne() (net.Conn, error) {
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

	req, err := http.NewRequestWithContext(httputils.NewAddrContext(&conn.NetAddr, c.ctx), http.MethodPost, requestURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		return nil, err
	}
	req.Host = c.cfg.Host

	if err = c.cfg.FillStreamRequest(req, ""); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		return nil, err
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		return nil, fmt.Errorf("xhttp stream-one bad status: %s", resp.Status)
	}
	conn.reader = resp.Body
	conn.onClose = func() {
		_ = pr.Close()
		httputils.CloseTransport(transport)
	}

	return conn, nil
}

func (c *Client) DialStreamUp() (net.Conn, error) {
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

	sessionID := newSessionID()

	downloadReq, err := http.NewRequestWithContext(
		httputils.NewAddrContext(&conn.NetAddr, c.ctx),
		http.MethodGet,
		downloadURL.String(),
		nil,
	)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}

	if err := downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	downloadReq.Host = downloadCfg.Host

	uploadReq, err := http.NewRequestWithContext(
		c.ctx,
		http.MethodPost,
		streamURL.String(),
		pr,
	)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}

	if err = c.cfg.FillStreamRequest(uploadReq, sessionID); err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	uploadReq.Host = c.cfg.Host

	downloadResp, err := downloadTransport.RoundTrip(downloadReq)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	if downloadResp.StatusCode != http.StatusOK {
		_ = downloadResp.Body.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, fmt.Errorf("xhttp stream-up download bad status: %s", downloadResp.Status)
	}

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

	conn.reader = downloadResp.Body
	conn.onClose = func() {
		_ = pr.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
	}

	return conn, nil
}

func (c *Client) DialPacketUp() (net.Conn, error) {
	uploadTransport, downloadTransport, err := c.getTransport()
	if err != nil {
		return nil, err
	}

	downloadCfg := c.cfg
	if ds := c.cfg.DownloadConfig; ds != nil {
		downloadCfg = ds
	}
	sessionID := newSessionID()

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

	downloadReq, err := http.NewRequestWithContext(
		httputils.NewAddrContext(&conn.NetAddr, c.ctx),
		http.MethodGet,
		downloadURL.String(),
		nil,
	)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	if err = downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	downloadReq.Host = downloadCfg.Host

	resp, err := downloadTransport.RoundTrip(downloadReq)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, fmt.Errorf("xhttp packet-up download bad status: %s", resp.Status)
	}

	conn.reader = resp.Body
	conn.onClose = func() {
		// uploadTransport already closed by writer
		httputils.CloseTransport(downloadTransport)
	}

	return conn, nil
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
