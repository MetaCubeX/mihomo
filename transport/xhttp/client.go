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

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)

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

func DialStreamOne(cfg *Config, transport http.RoundTripper) (net.Conn, error) {
	requestURL := url.URL{
		Scheme: "https",
		Host:   cfg.Host,
		Path:   cfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()

	ctx := context.Background()
	conn := &Conn{writer: pw}

	req, err := http.NewRequestWithContext(httputils.NewAddrContext(&conn.NetAddr, ctx), http.MethodPost, requestURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	req.Host = cfg.Host

	if err := cfg.FillStreamRequest(req, ""); err != nil {
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
		_ = resp.Body.Close()
		_ = pr.Close()
		httputils.CloseTransport(transport)
	}

	return conn, nil
}

func DialStreamUp(
	cfg *Config,
	uploadTransport http.RoundTripper,
	downloadTransport http.RoundTripper,
	address string,
	port int,
) (net.Conn, error) {
	host := cfg.Host
	if host == "" {
		host = address
	}

	downloadCfg := cfg
	if ds := cfg.DownloadSettings; ds != nil {
		downloadCfg = &Config{
			Host:             ds.Host,
			Path:             ds.Path,
			Mode:             ds.Mode,
			Headers:          cfg.Headers,
			NoGRPCHeader:     cfg.NoGRPCHeader,
			XPaddingBytes:    cfg.XPaddingBytes,
			DownloadSettings: nil,
		}
	}

	downloadHost := downloadCfg.Host
	if downloadHost == "" {
		downloadHost = host
	}

	_ = port

	streamURL := url.URL{
		Scheme: "https",
		Host:   host,
		Path:   cfg.NormalizedPath(),
	}

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadHost,
		Path:   downloadCfg.NormalizedPath(),
	}

	ctx := context.Background()
	conn := &Conn{}

	sessionID := newSessionID()

	downloadReq, err := http.NewRequestWithContext(
		httputils.NewAddrContext(&conn.NetAddr, contextutils.WithoutCancel(ctx)),
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
	downloadReq.Host = downloadHost

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

	pr, pw := io.Pipe()

	uploadReq, err := http.NewRequestWithContext(
		contextutils.WithoutCancel(ctx),
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

	if err := cfg.FillStreamRequest(uploadReq, sessionID); err != nil {
		_ = downloadResp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	uploadReq.Host = host

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

	conn.writer = pw
	conn.reader = downloadResp.Body
	conn.onClose = func() {
		_ = downloadResp.Body.Close()
		_ = pr.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
	}

	return conn, nil
}

func DialPacketUp(cfg *Config, transport http.RoundTripper) (net.Conn, error) {
	sessionID := newSessionID()

	downloadURL := url.URL{
		Scheme: "https",
		Host:   cfg.Host,
		Path:   cfg.NormalizedPath(),
	}

	ctx := context.Background()
	writer := &PacketUpWriter{
		ctx:       ctx,
		cfg:       cfg,
		sessionID: sessionID,
		transport: transport,
		seq:       0,
	}
	conn := &Conn{writer: writer}

	req, err := http.NewRequestWithContext(httputils.NewAddrContext(&conn.NetAddr, ctx), http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if err := cfg.FillDownloadRequest(req, sessionID); err != nil {
		return nil, err
	}
	req.Host = cfg.Host

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		httputils.CloseTransport(transport)
		return nil, fmt.Errorf("xhttp packet-up download bad status: %s", resp.Status)
	}
	conn.reader = resp.Body

	return conn, nil
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
