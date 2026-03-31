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
)

type RoundTripperFactory func(ctx context.Context) (http.RoundTripper, error)

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

	requestURL := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}

	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, requestURL.String(), nil)
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

func DialStreamOne(ctx context.Context, cfg *Config, newTransport RoundTripperFactory) (net.Conn, error) {
	transport, err := newTransport(ctx)
	if err != nil {
		return nil, err
	}
	requestURL := url.URL{
		Scheme: "https",
		Host:   cfg.Host,
		Path:   cfg.NormalizedPath(),
	}

	pr, pw := io.Pipe()
	conn := &Conn{writer: pw}

	req, err := http.NewRequestWithContext(httputils.NewAddrContext(&conn.NetAddr, contextutils.WithoutCancel(ctx)), http.MethodPost, requestURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		return nil, err
	}
	req.Host = cfg.Host

	if err := cfg.FillStreamRequest(req, ""); err != nil {
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
		_ = resp.Body.Close()
		_ = pr.Close()
		httputils.CloseTransport(transport)
	}

	return conn, nil
}

func DialStreamUp(
	ctx context.Context,
	cfg *Config,
	newUploadTransport RoundTripperFactory,
	newDownloadTransport RoundTripperFactory,
) (net.Conn, error) {
	uploadTransport, err := newUploadTransport(ctx)
	if err != nil {
		return nil, err
	}

	downloadTransport, err := newDownloadTransport(ctx)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		return nil, err
	}
	sessionID := newSessionID()
	downloadCfg := cfg.DownloadRequestConfig()

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}

	conn := &Conn{}

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

	uploadURL := url.URL{
		Scheme: "https",
		Host:   cfg.Host,
		Path:   cfg.NormalizedPath(),
	}

	pr, pw := io.Pipe()
	uploadReq, err := http.NewRequestWithContext(contextutils.WithoutCancel(ctx), http.MethodPost, uploadURL.String(), pr)
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
	uploadReq.Host = cfg.Host

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

func DialPacketUp(
	ctx context.Context,
	cfg *Config,
	newUploadTransport RoundTripperFactory,
	newDownloadTransport RoundTripperFactory,
) (net.Conn, error) {
	uploadTransport, err := newUploadTransport(ctx)
	if err != nil {
		return nil, err
	}

	downloadTransport, err := newDownloadTransport(ctx)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		return nil, err
	}

	sessionID := newSessionID()
	downloadCfg := cfg.DownloadRequestConfig()

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}

	ctx = contextutils.WithoutCancel(ctx)
	writer := &PacketUpWriter{
		ctx:       ctx,
		cfg:       cfg,
		sessionID: sessionID,
		transport: uploadTransport,
		seq:       0,
	}
	conn := &Conn{writer: writer}

	req, err := http.NewRequestWithContext(httputils.NewAddrContext(&conn.NetAddr, ctx), http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	if err := downloadCfg.FillDownloadRequest(req, sessionID); err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	req.Host = downloadCfg.Host

	resp, err := downloadTransport.RoundTrip(req)
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
		_ = resp.Body.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
	}

	return conn, nil
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
