package xhttp

import (
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
)

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)
type DialQUICFunc func(ctx context.Context, cfg *quic.Config) (*quic.Conn, error)

type TransportMaker func() http.RoundTripper

type PacketUpWriter struct {
	ctx                context.Context
	cancel             context.CancelFunc
	cfg                *Config
	scMaxEachPostBytes Range
	sessionID          string
	transport          http.RoundTripper
	writeMu            sync.Mutex
	seq                uint64
}

func (c *PacketUpWriter) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	scMaxEachPostBytes := c.scMaxEachPostBytes.Rand()
	if len(b) < scMaxEachPostBytes {
		return c.write(b)
	}
	var n int
	for start := 0; start < len(b); start += scMaxEachPostBytes {
		end := start + scMaxEachPostBytes
		if end > len(b) {
			end = len(b)
		}
		_n, err := c.write(b[start:end])
		n += _n
		if err != nil {
			return n, err
		}
	}
	return n, nil
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
	c.cancel()
	httputils.CloseTransport(c.transport)
	return nil
}

func NewTransport(dialRaw DialRawFunc, wrapTLS WrapTLSFunc, dialQUIC DialQUICFunc, alpn []string) http.RoundTripper {
	if len(alpn) == 1 && alpn[0] == "h3" { // `alpn: [h3]` means using h3 mode
		return &http3.Transport{
			QUICConfig: &quic.Config{
				MaxIncomingStreams: -1, // don't allow the server to create bidirectional streams
				KeepAlivePeriod:    10 * time.Second,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return dialQUIC(ctx, cfg)
			},
		}
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
	}
}

type Client struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	mode                  string
	cfg                   *Config
	scMaxEachPostBytes    Range
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
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		mode:                  mode,
		cfg:                   cfg,
		scMaxEachPostBytes:    scMaxEachPostBytes,
		makeTransport:         makeTransport,
		makeDownloadTransport: makeDownloadTransport,
		ctx:                   ctx,
		cancel:                cancel,
	}
	if cfg.ReuseConfig != nil {
		var err error
		client.uploadManager, err = NewReuseManager(cfg.ReuseConfig, makeTransport)
		if err != nil {
			return nil, err
		}
		if cfg.DownloadConfig != nil {
			if makeDownloadTransport == nil {
				return nil, fmt.Errorf("xhttp: download manager requires download transport maker")
			}
			client.downloadManager, err = NewReuseManager(cfg.DownloadConfig.ReuseConfig, makeDownloadTransport)
			if err != nil {
				return nil, err
			}
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
	if c.uploadManager == nil {
		uploadTransport = c.makeTransport()
		downloadTransport = onlyRoundTripper{uploadTransport}
		if c.makeDownloadTransport != nil {
			downloadTransport = c.makeDownloadTransport()
		}
	} else {
		uploadTransport, err = c.uploadManager.GetTransport()
		if err != nil {
			return
		}

		downloadTransport = onlyRoundTripper{uploadTransport}
		if c.downloadManager != nil {
			downloadTransport, err = c.downloadManager.GetTransport()
			if err != nil {
				httputils.CloseTransport(uploadTransport)
				return
			}
		}
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

	if err := c.cfg.FillStreamRequest(req, ""); err != nil {
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

	uploadReq, err := http.NewRequestWithContext(
		c.ctx,
		http.MethodPost,
		streamURL.String(),
		pr,
	)
	if err != nil {
		_ = downloadResp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}

	if err := c.cfg.FillStreamRequest(uploadReq, sessionID); err != nil {
		_ = downloadResp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	uploadReq.Host = c.cfg.Host

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
		ctx:                writerCtx,
		cancel:             writerCancel,
		cfg:                c.cfg,
		scMaxEachPostBytes: c.scMaxEachPostBytes,
		sessionID:          sessionID,
		transport:          uploadTransport,
		seq:                0,
	}
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
	if err := downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
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
