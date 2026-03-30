package xhttp

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/utils"
	ctls "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/log"
	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

func appendToPath(path string, sessionId string) string {
	if path == "" {
		return "/" + sessionId
	}
	if path[len(path)-1] == '/' {
		return path + sessionId
	}
	return path + "/" + sessionId
}

func getBaseRequest(ctx context.Context, method, urlStr string, body io.Reader, config *SplitHTTPConfig) (*http.Request, error) {
	// Keep SplitHTTP request lifecycle independent from outer dial context cancellation.
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), method, urlStr, body)
	if err != nil {
		return nil, err
	}
	return req, nil
}

type Conn struct {
	net.Conn
	reader     io.ReadCloser
	writer     io.WriteCloser
	localAddr  net.Addr
	remoteAddr net.Addr
	debug      bool
	rOnce      sync.Once
	wOnce      sync.Once
}

func NewConn(base net.Conn, reader io.ReadCloser, writer io.WriteCloser, debug bool) *Conn {
	return &Conn{
		Conn:   base,
		reader: reader,
		writer: writer,
		debug:  debug,
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.reader == nil {
		return 0, io.EOF
	}
	n, err = c.reader.Read(b)
	if c.debug && err != nil {
		c.rOnce.Do(func() {
			log.Infoln("splithttp[conn-read] n=%d err=%v", n, err)
		})
	}
	return n, err
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.writer == nil {
		return 0, io.ErrClosedPipe
	}
	n, err = c.writer.Write(b)
	if c.debug && err != nil {
		c.wOnce.Do(func() {
			log.Infoln("splithttp[conn-write] n=%d err=%v", n, err)
		})
	}
	return n, err
}

func (c *Conn) Close() error {
	var errs []error
	if c.reader != nil {
		if err := c.reader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.writer != nil {
		if err := c.writer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := c.Conn.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	if c.Conn != nil {
		return c.Conn.LocalAddr()
	}
	return nil
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	if c.Conn != nil {
		return c.Conn.RemoteAddr()
	}
	return nil
}

type WaitReadCloser struct {
	Wait chan struct{}
	io.ReadCloser
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.ReadCloser = rc
	defer func() {
		if recover() != nil {
			rc.Close()
		}
	}()
	close(w.Wait)
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	if w.ReadCloser == nil {
		if <-w.Wait; w.ReadCloser == nil {
			return 0, io.ErrClosedPipe
		}
	}
	return w.ReadCloser.Read(b)
}

func (w *WaitReadCloser) Close() error {
	if w.ReadCloser != nil {
		return w.ReadCloser.Close()
	}
	defer func() {
		if recover() != nil && w.ReadCloser != nil {
			w.ReadCloser.Close()
		}
	}()
	close(w.Wait)
	return nil
}

func parseMode(config *SplitHTTPConfig) string {
	if config.Mode != "" && config.Mode != "auto" {
		return config.Mode
	}
	return "packet-up"
}

type connTelemetry struct {
	localAddr  string
	remoteAddr string
}

func getConnTelemetry(c net.Conn) connTelemetry {
	baseConn := c
	meta := connTelemetry{}
	if baseConn != nil {
		if l := baseConn.LocalAddr(); l != nil {
			meta.localAddr = l.String()
		}
		if r := baseConn.RemoteAddr(); r != nil {
			meta.remoteAddr = r.String()
		}
	}
	return meta
}

func logRequest(config *SplitHTTPConfig, stage string, req *http.Request, sessionID string, seqStr string, meta connTelemetry) {
	if !config.RequestLog {
		return
	}
	log.Infoln("splithttp[%s] %s %s host=%s session=%s seq=%s meta={%s} local=%s remote=%s headers={%s}",
		stage,
		req.Method,
		req.URL.String(),
		req.Host,
		sessionID,
		seqStr,
		config.MetaSummary(req),
		meta.localAddr,
		meta.remoteAddr,
		config.HeaderSummary(req),
	)
}

func logResponse(config *SplitHTTPConfig, stage string, resp *http.Response, sessionID string, seqStr string, meta connTelemetry) {
	if !config.RequestLog || resp == nil {
		return
	}
	server := resp.Header.Get("Server")
	if server == "" {
		server = "Unknown"
	}
	cfRayPart := ""
	if cfRay := resp.Header.Get("Cf-Ray"); cfRay != "" {
		cfRayPart = " cf-ray=" + cfRay
	}
	log.Infoln("splithttp[%s-resp] status=%d session=%s seq=%s actual_http=%s local=%s remote=%s server=%s%s content-length=%s",
		stage,
		resp.StatusCode,
		sessionID,
		seqStr,
		resp.Proto,
		meta.localAddr,
		meta.remoteAddr,
		server,
		cfRayPart,
		resp.Header.Get("Content-Length"),
	)
}

func ensureHTTPProtocolAllowed(config *SplitHTTPConfig, resp *http.Response) error {
	if resp == nil {
		return nil
	}
	if config.IsHTTPProtoAllowed(resp.Proto) {
		return nil
	}
	return fmt.Errorf("splithttp protocol mismatch: actual=%s not allowed by alpn=%v", resp.Proto, config.ALPN)
}

// PacketUpWriter splits Write calls into separate HTTP requests
type PacketUpWriter struct {
	ctx       context.Context
	client    DialerClient
	url       string
	config    *SplitHTTPConfig
	sessionId string
	seq       int64
	closed    bool
	mu        sync.Mutex
	meta      connTelemetry

	h1RawUpload    bool
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctx context.Context) (net.Conn, error)
}

func (w *PacketUpWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	seqStr := strconv.FormatInt(w.seq, 10)
	w.seq++
	w.mu.Unlock()

	req, err := getBaseRequest(w.ctx, w.config.GetNormalizedUplinkHTTPMethod(), w.url, nil, w.config)
	if err != nil {
		return 0, err
	}
	w.config.FillPacketRequest(req, w.sessionId, seqStr, b)
	logRequest(w.config, "packet-up", req, w.sessionId, seqStr, w.meta)
	if err := w.client.PostPacket(w.ctx, w.url, w.sessionId, seqStr, append([]byte(nil), b...)); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *PacketUpWriter) Close() error {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	return nil
}

type noopNetConn struct{}

func (noopNetConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (noopNetConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (noopNetConn) Close() error                     { return nil }
func (noopNetConn) LocalAddr() net.Addr              { return nil }
func (noopNetConn) RemoteAddr() net.Addr             { return nil }
func (noopNetConn) SetDeadline(time.Time) error      { return nil }
func (noopNetConn) SetReadDeadline(time.Time) error  { return nil }
func (noopNetConn) SetWriteDeadline(time.Time) error { return nil }

func buildRequestURL(config *SplitHTTPConfig) string {
	scheme := "https"
	if !config.TLS {
		scheme = "http"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, config.Host, config.GetNormalizedPath())
	if rawQuery := config.GetNormalizedQuery(); rawQuery != "" {
		url += "?" + rawQuery
	}
	return url
}

func streamConnWithDialerClient(ctx context.Context, client DialerClient, base net.Conn, config *SplitHTTPConfig, connMeta connTelemetry) (net.Conn, error) {
	mode := parseMode(config)
	sessionID := ""
	if mode != "stream-one" {
		sessionID = utils.NewUUIDV4().String()
	}
	url := buildRequestURL(config)

	if mode == "stream-one" {
		pr, pw := io.Pipe()
		req, err := getBaseRequest(ctx, config.GetNormalizedUplinkHTTPMethod(), url, pr, config)
		if err != nil {
			return nil, fmt.Errorf("create req failed: %w", err)
		}
		config.FillStreamRequest(req, sessionID)
		logRequest(config, "stream-one", req, sessionID, "", connMeta)
		reader, remoteAddr, localAddr, err := client.OpenStream(ctx, url, sessionID, pr, false)
		if err != nil {
			_ = pr.Close()
			_ = pw.Close()
			return nil, err
		}
		conn := NewConn(base, reader, pw, config.RequestLog)
		conn.localAddr = localAddr
		conn.remoteAddr = remoteAddr
		return conn, nil
	}

	req, err := getBaseRequest(ctx, http.MethodGet, url, nil, config)
	if err != nil {
		return nil, fmt.Errorf("create stream-down req failed: %w", err)
	}
	config.FillStreamRequest(req, sessionID)
	logRequest(config, "stream-down", req, sessionID, "", connMeta)

	reader, remoteAddr, localAddr, err := client.OpenStream(ctx, url, sessionID, nil, false)
	if err != nil {
		return nil, err
	}
	conn := NewConn(base, reader, nil, config.RequestLog)
	conn.localAddr = localAddr
	conn.remoteAddr = remoteAddr

	if mode == "stream-up" {
		upReader, upWriter := io.Pipe()
		req, err := getBaseRequest(ctx, config.GetNormalizedUplinkHTTPMethod(), url, upReader, config)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("create stream-up req failed: %w", err)
		}
		config.FillStreamRequest(req, sessionID)
		logRequest(config, "stream-up", req, sessionID, "", connMeta)
		if _, _, _, err := client.OpenStream(ctx, url, sessionID, upReader, true); err != nil {
			_ = conn.Close()
			_ = upReader.Close()
			_ = upWriter.Close()
			return nil, err
		}
		conn.writer = upWriter
		return conn, nil
	}

	if mode == "packet-up" {
		req, err := getBaseRequest(ctx, config.GetNormalizedUplinkHTTPMethod(), url, nil, config)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("create packet-up req failed: %w", err)
		}
		config.FillPacketRequest(req, sessionID, "0", nil)
		writer := &PacketUpWriter{
			ctx:       ctx,
			client:    client,
			url:       url,
			config:    config,
			sessionId: sessionID,
			meta:      connMeta,
		}
		conn.writer = writer
		return conn, nil
	}

	_ = conn.Close()
	return nil, fmt.Errorf("unsupported splithttp mode %s", mode)
}

func buildHTTP3Client(config *SplitHTTPConfig) *http.Client {
	tlsServerName := config.TLSServerName
	if tlsServerName == "" {
		tlsServerName = config.Host
	}
	tlsConf := &tls.Config{
		ServerName: tlsServerName,
		NextProtos: []string{"h3"},
	}
	quicConf := &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
	}
	rt := &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig:      quicConf,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", config.DialAddr)
			if err != nil {
				return nil, err
			}

			var conn net.PacketConn
			if config.H3PacketDial != nil {
				conn, err = config.H3PacketDial(ctx, udpAddr)
			} else {
				conn, err = net.ListenPacket("udp", ":0")
			}
			if err != nil {
				return nil, err
			}

			if tlsCfg == nil {
				tlsCfg = tlsConf.Clone()
			} else {
				tlsCfg = tlsCfg.Clone()
			}
			if tlsCfg.ServerName == "" {
				tlsCfg.ServerName = tlsServerName
			}
			if len(tlsCfg.NextProtos) == 0 {
				tlsCfg.NextProtos = []string{"h3"}
			}

			quicConn, err := quic.DialEarly(ctx, conn, udpAddr, tlsCfg, cfg)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return quicConn, nil
		},
	}
	return &http.Client{Transport: rt}
}

func StreamConnH3(ctx context.Context, config *SplitHTTPConfig) (net.Conn, error) {
	connMeta := connTelemetry{localAddr: "unknown", remoteAddr: config.DialAddr}
	return streamConnWithDialerClient(ctx, getH3DialerClient(config), noopNetConn{}, config, connMeta)
}

// StreamConn builds either Stream-One, Stream-Up/Down, or Packet-Up multiplexed flow based on configs.
func StreamConn(ctx context.Context, c net.Conn, config *SplitHTTPConfig) (net.Conn, error) {
	mode := parseMode(config)
	connMeta := getConnTelemetry(c)

	// Select transport explicitly to avoid parsing HTTP/2 frames with HTTP/1 reader.
	useH2 := config.HasALPN("h2")
	negotiatedProto := ""
	if hs, ok := c.(interface{ HandshakeContext(context.Context) error }); ok {
		_ = hs.HandshakeContext(ctx)
	} else if hs, ok := c.(interface{ Handshake() error }); ok {
		_ = hs.Handshake()
	}
	if ts, ok := c.(interface{ ConnectionState() tls.ConnectionState }); ok {
		negotiatedProto = ts.ConnectionState().NegotiatedProtocol
	} else if ts, ok := c.(interface{ ConnectionState() ctls.ConnectionState }); ok {
		negotiatedProto = ts.ConnectionState().NegotiatedProtocol
	}
	if negotiatedProto != "" {
		useH2 = negotiatedProto == "h2"
	} else if !config.HasALPN("h2") {
		useH2 = false
	}
	if config.RequestLog {
		log.Infoln("splithttp[transport-select] requested_alpn=%v negotiated=%s use_h2=%v mode=%s", config.ALPN, negotiatedProto, useH2, mode)
	}
	var rt http.RoundTripper
	if useH2 {
		rt = &http.Http2Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return c, nil
			},
			ReadIdleTimeout: 30 * time.Second,
		}
	} else {
		rt = &http.Transport{
			ForceAttemptHTTP2: false,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return c, nil
			},
		}
	}

	client := &http.Client{
		Transport: rt,
	}
	httpVersion := "2"
	if !useH2 {
		httpVersion = "1.1"
		if config.H1UploadDial == nil && (mode == "stream-up" || mode == "packet-up") {
			return nil, fmt.Errorf("splithttp %s requires h1-upload-dial when HTTP/2 is unavailable", mode)
		}
	}
	dialerClient := &DefaultDialerClient{
		transportConfig: config,
		client:          client,
		httpVersion:     httpVersion,
		uploadRawPool:   &sync.Pool{},
		dialUploadConn:  config.H1UploadDial,
	}
	return streamConnWithDialerClient(ctx, dialerClient, c, config, connMeta)
}
