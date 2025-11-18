package xhttp

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/quic-go"
	http3 "github.com/metacubex/quic-go/http3"
	tls "github.com/metacubex/utls"
	"golang.org/x/net/http2"
)

// DialFunc dials the remote endpoint using the provided network (e.g. "tcp" or "udp").
type DialFunc func(ctx context.Context, network string) (net.Conn, error)

// Options configures the Dial call.
type Options struct {
	Dial         DialFunc
	Config       *Config
	Scheme       string
	HostHeader   string
	Address      string
	HTTPVersion  string
	PreferStream bool
	Tag          string
}

type endpoint struct {
	cfg         *Config
	url         *url.URL
	client      *http.Client
	httpVersion string
	releaseOnce sync.Once
	releaseFunc func()
}

func (e *endpoint) release() {
	if e == nil || e.releaseFunc == nil {
		return
	}
	e.releaseOnce.Do(func() {
		e.releaseFunc()
	})
}

// Dial establishes an XHTTP (SplitHTTP) connection and returns a net.Conn compatible stream.
func Dial(ctx context.Context, opts Options) (net.Conn, error) {
	if opts.Dial == nil {
		return nil, errors.New("xhttp: DialFunc is required")
	}

	cfg := opts.Config.clone()
	cfg.normalize()

	var downloadCfg *Config
	if cfg.Download != nil {
		downloadCfg = cfg.Download.clone()
		downloadCfg.normalize()
	} else {
		downloadCfg = cfg
	}

	sessionID := uuid.Must(uuid.NewV4()).String()

	uploadEP, err := prepareEndpoint(cfg, opts, sessionID, false)
	if err != nil {
		return nil, err
	}

	downloadEP := uploadEP
	if downloadCfg != cfg {
		downloadEP, err = prepareEndpoint(downloadCfg, opts, sessionID, true)
		if err != nil {
			uploadEP.release()
			return nil, err
		}
	}

	mode := resolveMode(cfg.Mode, opts.PreferStream, downloadCfg != cfg)
	logTag := opts.Tag
	if logTag == "" {
		logTag = "xhttp"
	}
	log.Debugln("%s: dialing %s via %s (mode=%s, http=%s)", logTag, opts.Address, uploadEP.url, mode, uploadEP.httpVersion)

	ctx, cancel := context.WithCancel(ctx)

	var conn net.Conn
	switch mode {
	case "stream-one":
		conn, err = dialStreamOne(ctx, cancel, uploadEP)
	case "stream-up":
		conn, err = dialStreamUp(ctx, cancel, uploadEP, downloadEP)
	default:
		conn, err = dialPacketUp(ctx, cancel, uploadEP, downloadEP)
	}
	if err != nil {
		cancel()
		uploadEP.release()
		if downloadEP != uploadEP {
			downloadEP.release()
		}
		return nil, err
	}

	return conn, nil
}

func resolveMode(mode string, preferStream bool, hasDownload bool) string {
	switch strings.ToLower(mode) {
	case "stream-one", "stream-up", "packet-up":
		return mode
	}
	if preferStream {
		if hasDownload {
			return "stream-up"
		}
		return "stream-one"
	}
	return "packet-up"
}

func prepareEndpoint(cfg *Config, opts Options, sessionID string, isDownload bool) (*endpoint, error) {
	scheme := opts.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := firstNonEmpty(cfg.Host, opts.HostHeader, extractHost(opts.Address))
	if host == "" {
		host = "127.0.0.1"
	}

	httpVersion := cfg.httpVersion(strings.EqualFold(scheme, "https"))
	if opts.HTTPVersion != "" {
		httpVersion = strings.ToLower(opts.HTTPVersion)
	}
	if httpVersion == "3" {
		scheme = "https"
	}

	baseURL := buildBaseURL(cfg, scheme, host, sessionID)

	xmuxCfg := cfg.normalizedXmux()
	key := fmt.Sprintf("%s|%s|%s|%s|%t", opts.Address, host, cfg.Path, httpVersion, isDownload)

	slot, err := acquireClient(key, xmuxCfg, func() (*clientSlot, error) {
		uses, requests, expiry := xmuxCfg.newSlotLimits()
		client, transport, err := newHTTPClient(httpVersion, func(ctx context.Context, network string) (net.Conn, error) {
			target := "tcp"
			if network != "" {
				target = network
			}
			if httpVersion == "3" {
				target = "udp"
			}
			return opts.Dial(ctx, target)
		}, xmuxCfg.keepAlive, cfg.internalTLSConfig(), host)
		if err != nil {
			return nil, err
		}
		return &clientSlot{
			client:           client,
			transport:        transport,
			cfg:              xmuxCfg,
			remainingUses:    uses,
			remainingRequest: requests,
			expiry:           expiry,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	if slot == nil {
		return nil, errors.New("xhttp: unable to acquire client")
	}

	return &endpoint{
		cfg:         cfg,
		url:         baseURL,
		client:      slot.client,
		httpVersion: httpVersion,
		releaseFunc: slot.release,
	}, nil
}

func dialStreamOne(ctx context.Context, cancel context.CancelFunc, ep *endpoint) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.url.String(), pr)
	if err != nil {
		return nil, err
	}
	applyHeaders(req, ep.cfg, ep.url)
	if ep.cfg.NoGRPCHeader {
		req.Header.Del("Content-Type")
	}

	resp, remoteAddr, localAddr, err := doRequest(ep.client, req)
	if err != nil {
		return nil, err
	}

	conn := &splitConn{
		reader: resp.Body,
		writer: &pipeWriter{PipeWriter: pw},
		remote: remoteAddr,
		local:  localAddr,
		onClose: func() {
			cancel()
			_ = pw.Close()
			_ = resp.Body.Close()
			ep.release()
		},
	}
	return conn, nil
}

func dialStreamUp(ctx context.Context, cancel context.CancelFunc, uploadEP, downloadEP *endpoint) (net.Conn, error) {
	downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadEP.url.String(), nil)
	if err != nil {
		return nil, err
	}
	applyHeaders(downloadReq, downloadEP.cfg, downloadEP.url)
	if !downloadEP.cfg.NoSSEHeader {
		downloadReq.Header.Set("Content-Type", "text/event-stream")
	}

	downloadResp, remoteAddr, localAddr, err := doRequest(downloadEP.client, downloadReq)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadEP.url.String(), pr)
	if err != nil {
		_ = downloadResp.Body.Close()
		return nil, err
	}
	applyHeaders(uploadReq, uploadEP.cfg, uploadEP.url)
	if uploadEP.cfg.NoGRPCHeader {
		uploadReq.Header.Del("Content-Type")
	}

	go func() {
		resp, err := uploadEP.client.Do(uploadReq)
		if err != nil {
			pr.CloseWithError(err)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	conn := &splitConn{
		reader: downloadResp.Body,
		writer: &pipeWriter{PipeWriter: pw},
		remote: remoteAddr,
		local:  localAddr,
		onClose: func() {
			cancel()
			_ = pw.Close()
			_ = downloadResp.Body.Close()
			uploadEP.release()
			downloadEP.release()
		},
	}
	return conn, nil
}

func dialPacketUp(ctx context.Context, cancel context.CancelFunc, uploadEP, downloadEP *endpoint) (net.Conn, error) {
	downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadEP.url.String(), nil)
	if err != nil {
		return nil, err
	}
	applyHeaders(downloadReq, downloadEP.cfg, downloadEP.url)
	if !downloadEP.cfg.NoSSEHeader {
		downloadReq.Header.Set("Content-Type", "text/event-stream")
	}

	downloadResp, remoteAddr, localAddr, err := doRequest(downloadEP.client, downloadReq)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	conn := &splitConn{
		reader: downloadResp.Body,
		writer: &pipeWriter{PipeWriter: pw},
		remote: remoteAddr,
		local:  localAddr,
		onClose: func() {
			cancel()
			_ = pw.Close()
			_ = downloadResp.Body.Close()
			uploadEP.release()
			downloadEP.release()
		},
	}

	go handleUploads(ctx, uploadEP, pr)

	return conn, nil
}

func handleUploads(ctx context.Context, ep *endpoint, reader *io.PipeReader) {
	defer reader.Close()
	maxPostBytes := int(ep.cfg.ScMaxEachPostBytes.Random())
	if maxPostBytes <= 0 {
		maxPostBytes = 1024 * 1024
	}
	buf := make([]byte, maxPostBytes)
	seq := int64(0)
	interval := time.Duration(ep.cfg.ScMinPostsIntervalMs.Random()) * time.Millisecond
	basePath := strings.TrimSuffix(ep.url.Path, "/")

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			urlCopy := *ep.url
			urlCopy.Path = fmt.Sprintf("%s/%d", basePath, seq)
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, urlCopy.String(), bytes.NewReader(buf[:n]))
			if reqErr != nil {
				reader.CloseWithError(reqErr)
				return
			}
			applyHeaders(req, ep.cfg, ep.url)
			if ep.cfg.NoGRPCHeader {
				req.Header.Del("Content-Type")
			}
			if resp, reqErr := ep.client.Do(req); reqErr != nil {
				reader.CloseWithError(reqErr)
				return
			} else {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			seq++
			if interval > 0 {
				select {
				case <-time.After(interval):
				case <-ctx.Done():
					reader.CloseWithError(ctx.Err())
					return
				}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				reader.CloseWithError(err)
			}
			return
		}
	}
}

func applyHeaders(req *http.Request, cfg *Config, baseURL *url.URL) {
	for k, v := range cfg.Headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		req.Header.Set(k, v)
	}
	req.Host = baseURL.Host
	req.Header.Set("Referer", withPadding(baseURL.String(), int(cfg.XPaddingBytes.Random())))
	if req.Method == http.MethodPost && !cfg.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}
}

func doRequest(client *http.Client, req *http.Request) (*http.Response, net.Addr, net.Addr, error) {
	var remoteAddr, localAddr net.Addr
	gotConn := make(chan struct{}, 1)
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			remoteAddr = info.Conn.RemoteAddr()
			localAddr = info.Conn.LocalAddr()
			select {
			case gotConn <- struct{}{}:
			default:
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	select {
	case <-gotConn:
	default:
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, nil, nil, fmt.Errorf("xhttp: unexpected status %d", resp.StatusCode)
	}
	return resp, remoteAddr, localAddr, nil
}

func newHTTPClient(httpVersion string, dial DialFunc, keepAlive time.Duration, tlsCfg *tls.Config, host string) (*http.Client, http.RoundTripper, error) {
	if keepAlive <= 0 {
		keepAlive = 30 * time.Second
	}
	switch httpVersion {
	case "3":
		if tlsCfg == nil {
			tlsCfg = &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: host,
			}
		}
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = host
		}
		if len(tlsCfg.NextProtos) == 0 {
			tlsCfg.NextProtos = []string{"h3"}
		}
		quicCfg := &quic.Config{
			KeepAlivePeriod: keepAlive,
			MaxIdleTimeout:  keepAlive * 2,
		}
		transport := &http3.Transport{
			TLSClientConfig: tlsCfg,
			QUICConfig:      quicCfg,
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				conn, err := dial(ctx, "udp")
				if err != nil {
					return nil, err
				}
				packetConn, ok := conn.(net.PacketConn)
				if !ok {
					return nil, fmt.Errorf("xhttp: http3 requires UDP connection")
				}
				udpAddr, err := net.ResolveUDPAddr("udp", addr)
				if err != nil {
					return nil, err
				}
				return quic.DialEarly(ctx, packetConn, udpAddr, tlsCfg, cfg)
			},
		}
		return &http.Client{Transport: transport}, transport, nil
	case "2":
		transport := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *stdtls.Config) (net.Conn, error) {
				return dial(ctx, "tcp")
			},
			IdleConnTimeout: keepAlive,
			ReadIdleTimeout: keepAlive,
		}
		return &http.Client{Transport: transport}, transport, nil
	default:
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dial(ctx, "tcp")
			},
			IdleConnTimeout:     keepAlive,
			MaxIdleConnsPerHost: 4,
		}
		return &http.Client{Transport: transport}, transport, nil
	}
}

type pipeWriter struct {
	*io.PipeWriter
	closed atomic.Bool
}

func (w *pipeWriter) Close() error {
	if w.closed.CompareAndSwap(false, true) {
		return w.PipeWriter.Close()
	}
	return nil
}

func (w *pipeWriter) Write(b []byte) (int, error) {
	return w.PipeWriter.Write(b)
}

func buildBaseURL(cfg *Config, scheme, host, sessionID string) *url.URL {
	u := &url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   cfg.Path + sessionID,
	}
	return u
}

func extractHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return address
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
