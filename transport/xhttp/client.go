package xhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)

type TransportMaker func() http.RoundTripper

type PacketUpWriter struct {
	ctx       context.Context
	cfg       *Config
	sessionID string
	transport http.RoundTripper
	writeMu   sync.Mutex
	seq       uint64
}

func (c *PacketUpWriter) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

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
	httputils.CloseTransport(c.transport)
	return nil
}

func NewTransport(dialRaw DialRawFunc, wrapTLS WrapTLSFunc) http.RoundTripper {
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
	mode                  string
	cfg                   *Config
	makeTransport         TransportMaker
	makeDownloadTransport TransportMaker
	ctx                   context.Context
	cancel                context.CancelFunc
}

func NewClient(cfg *Config, makeTransport TransportMaker, makeDownloadTransport TransportMaker, hasReality bool) (*Client, error) {
	mode := cfg.EffectiveMode(hasReality)
	switch mode {
	case "stream-one", "stream-up", "packet-up":
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", mode)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		mode:                  mode,
		cfg:                   cfg,
		makeTransport:         makeTransport,
		makeDownloadTransport: makeDownloadTransport,
		ctx:                   ctx,
		cancel:                cancel,
	}, nil
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

func (c *Client) Close() error {
	c.cancel()
	return nil
}

func (c *Client) DialStreamOne() (net.Conn, error) {
	transport := c.makeTransport()

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
		return nil, err
	}
	req.Host = c.cfg.Host

	if err := c.cfg.FillStreamRequest(req, ""); err != nil {
		_ = pr.Close()
		_ = pw.Close()
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
	uploadTransport := c.makeTransport()
	downloadTransport := uploadTransport
	if c.makeDownloadTransport != nil {
		downloadTransport = c.makeDownloadTransport()
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
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		return nil, err
	}

	if err := downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		return nil, err
	}
	downloadReq.Host = downloadCfg.Host

	downloadResp, err := downloadTransport.RoundTrip(downloadReq)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		return nil, err
	}
	if downloadResp.StatusCode != http.StatusOK {
		_ = downloadResp.Body.Close()
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
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
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		return nil, err
	}

	if err := c.cfg.FillStreamRequest(uploadReq, sessionID); err != nil {
		_ = downloadResp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
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
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
	}

	return conn, nil
}

func (c *Client) DialPacketUp() (net.Conn, error) {
	uploadTransport := c.makeTransport()
	downloadTransport := uploadTransport
	if c.makeDownloadTransport != nil {
		downloadTransport = c.makeDownloadTransport()
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

	writer := &PacketUpWriter{
		ctx:       c.ctx,
		cfg:       c.cfg,
		sessionID: sessionID,
		transport: uploadTransport,
		seq:       0,
	}
	conn := &Conn{writer: writer}

	downloadReq, err := http.NewRequestWithContext(httputils.NewAddrContext(&conn.NetAddr, c.ctx), http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if err := downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
		return nil, err
	}
	downloadReq.Host = downloadCfg.Host

	resp, err := downloadTransport.RoundTrip(downloadReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		return nil, fmt.Errorf("xhttp packet-up download bad status: %s", resp.Status)
	}
	conn.reader = resp.Body
	conn.onClose = func() {
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
	}

	return conn, nil
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
