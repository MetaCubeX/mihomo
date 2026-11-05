package httpmask

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httputil"
	"github.com/metacubex/mihomo/common/pool"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TunnelServerOptions struct {
	Mode string
	// PathRoot is an optional first-level path prefix for all HTTP tunnel endpoints.
	// Example: "aabbcc" => "/aabbcc/session", "/aabbcc/api/v1/upload", ...
	PathRoot string
	// AuthKey enables the optional WebSocket HMAC anti-probing layer. Stream and
	// poll sessions do not use a second HTTP-level authentication protocol.
	AuthKey string
	// AuthSkew controls allowed clock skew / replay window for AuthKey. 0 uses a conservative default.
	AuthSkew time.Duration
	// PassThroughOnReject controls how the server handles "recognized but rejected" tunnel requests
	// (e.g., wrong mode / wrong path / invalid token). When true, the request bytes are replayed back
	// to the caller as HandlePassThrough to allow higher-level fallback handling.
	PassThroughOnReject bool
	// PullReadTimeout controls how long the server long-poll waits for tunnel downlink data before replying.
	PullReadTimeout time.Duration
	// SessionTTL is a best-effort TTL to prevent leaked sessions. 0 uses a conservative default.
	SessionTTL time.Duration
	// EarlyHandshake optionally folds the protocol handshake into the initial HTTP/WS round trip.
	EarlyHandshake *TunnelServerEarlyHandshake
}

type TunnelServer struct {
	mode                TunnelMode
	pathRoot            string
	passThroughOnReject bool
	// auth is used only by the WebSocket transport.
	auth *tunnelAuth

	pullReadTimeout time.Duration
	sessionTTL      time.Duration
	earlyHandshake  *TunnelServerEarlyHandshake

	mu       sync.Mutex
	sessions map[string]*tunnelSession
}

const (
	tunnelHeaderReadTimeout = 15 * time.Second
	minReapInterval         = 50 * time.Millisecond
)

type tunnelSession struct {
	conn           *halfPipeConn
	lastActive     time.Time   // guarded by TunnelServer.mu
	uplinkClosed   bool        // guarded by TunnelServer.mu
	downlinkClosed bool        // guarded by TunnelServer.mu
	reaper         *time.Timer // set under TunnelServer.mu before the session is visible

	uploadMu      sync.Mutex
	nextUploadSeq uint64
	// Lock order: pullMu before TunnelServer.mu.
	pullMu          sync.Mutex
	pull            *sessionPullLease
	pendingDownlink []byte // owned by the current pull lease holder
}

type sessionPullLease struct {
	cancel   chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	rawConn  net.Conn
}

func newSessionPullLease(rawConn net.Conn) *sessionPullLease {
	return &sessionPullLease{
		cancel:  make(chan struct{}),
		done:    make(chan struct{}),
		rawConn: rawConn,
	}
}

func (p *sessionPullLease) stop() {
	if p != nil {
		p.stopOnce.Do(func() {
			close(p.cancel)
			if p.rawConn != nil {
				_ = p.rawConn.Close()
			}
		})
	}
}

var (
	errUploadSequenceGap = errors.New("upload sequence gap")
	errUploadTooLarge    = errors.New("upload too large")
)

type sessionDirection uint8

const (
	sessionUplink sessionDirection = iota
	sessionDownlink
)

func NewTunnelServer(opts TunnelServerOptions) *TunnelServer {
	mode := normalizeTunnelMode(opts.Mode)
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
		passThroughOnReject: opts.PassThroughOnReject,
		auth:                auth,
		pullReadTimeout:     timeout,
		sessionTTL:          ttl,
		earlyHandshake:      opts.EarlyHandshake,
		sessions:            make(map[string]*tunnelSession),
	}
}

// HandleConn inspects rawConn. If it is an HTTP tunnel request (stream/poll), it is handled here and:
//   - returns HandleStartTunnel + a net.Conn that carries the raw Sudoku stream (stream or poll session pipe)
//   - or returns HandleDone if the HTTP request is a poll control request (push/pull) and no Sudoku handshake should run on this TCP conn
//
// If it is not an HTTP tunnel request (or server mode is legacy), it returns HandlePassThrough with a conn that replays any pre-read bytes.
func (s *TunnelServer) HandleConn(rawConn net.Conn) (HandleResult, net.Conn, error) {
	if rawConn == nil {
		return HandleDone, nil, errors.New("nil conn")
	}

	passThrough := func(prefix []byte) (HandleResult, net.Conn, error) {
		return HandlePassThrough, newPreBufferedConn(rawConn, prefix), nil
	}
	passThroughRejected := func(prefix []byte) (HandleResult, net.Conn, error) {
		return HandlePassThrough, newRejectedPreBufferedConn(rawConn, prefix), nil
	}
	rejectOr404 := func(prefix []byte) (HandleResult, net.Conn, error) {
		if s.passThroughOnReject {
			return passThroughRejected(prefix)
		}
		return replyDone(rawConn, http.StatusNotFound, "not found")
	}

	// Preconnected HTTP sockets may wait for the client to assign their first
	// request after the TCP/TLS handshake. Keep this bounded, but longer than
	// the client's preconnect lease so high-RTT links do not turn a prepared
	// socket into a reset connection before net/http can use it.
	_ = rawConn.SetReadDeadline(time.Now().Add(tunnelHeaderReadTimeout))
	var first [4]byte
	n, err := io.ReadFull(rawConn, first[:])
	if err != nil {
		_ = rawConn.SetReadDeadline(time.Time{})
		// Even if short-read, preserve bytes for downstream handlers.
		if n > 0 {
			return passThrough(first[:n])
		}
		return HandleDone, nil, err
	}
	pc := newPreBufferedConn(rawConn, first[:])
	br := bufio.NewReader(pc)

	if !LooksLikeHTTPRequestStart(first[:]) {
		_ = rawConn.SetReadDeadline(time.Time{})
		return HandlePassThrough, pc, nil
	}

	req, unparsed, err := readHTTPRequest(rawConn, br, first[:])
	_ = rawConn.SetReadDeadline(time.Time{})
	if err != nil {
		// Not a valid HTTP request; hand it back to the legacy path with replay.
		return passThrough(unparsed)
	}

	tunnelHeader := TunnelMode(strings.ToLower(strings.TrimSpace(req.tunnel)))
	if req.isWebSocketUpgrade() {
		tunnelHeader = TunnelModeWS
	}
	if tunnelHeader == "" {
		// The explicit mode header is part of the stream/poll protocol. A request
		// without it belongs to the normal HTTP fallback path.
		return passThrough(req.replayPrefix())
	}

	if s.mode == TunnelModeLegacy {
		return rejectOr404(req.replayPrefix())
	}

	switch tunnelHeader {
	case TunnelModeStream:
		if s.mode != TunnelModeStream && s.mode != TunnelModeAuto {
			return rejectOr404(req.replayPrefix())
		}
		return s.handleSession(req, streamCodec)
	case TunnelModePoll:
		if s.mode != TunnelModePoll && s.mode != TunnelModeAuto {
			return rejectOr404(req.replayPrefix())
		}
		return s.handleSession(req, pollCodec)
	case TunnelModeWS:
		if s.mode != TunnelModeWS && s.mode != TunnelModeAuto {
			return rejectOr404(req.replayPrefix())
		}
		return s.handleWS(req)
	default:
		return rejectOr404(req.replayPrefix())
	}
}

func buildInvalidHTTPReplayPrefix(first, headerBytes, buffered []byte) []byte {
	// readHTTPHeader may have consumed some bytes that don't include our initial 4-byte peek
	// (e.g. parse errors / short reads). Preserve a correct replay prefix for downstream handlers.
	out := make([]byte, 0, len(first)+len(headerBytes)+len(buffered))
	if len(headerBytes) == 0 || !bytes.HasPrefix(headerBytes, first) {
		out = append(out, first...)
	}
	out = append(out, headerBytes...)
	out = append(out, buffered...)
	return out
}

const maxHTTPHeaderBytes = 32 * 1024

// headerBytesSizeHint covers a typical tunnel request header in one allocation.
const headerBytesSizeHint = 512

// tunnelRequest is a parsed HTTP request. br still holds the bytes read past the header, so the body is served
// from it directly and a rejected request can be replayed byte for byte.
type tunnelRequest struct {
	conn        net.Conn
	br          *bufio.Reader
	headerBytes []byte

	method string
	target string // path + query
	proto  string
	// Header values are the first occurrence, space-trimmed; only the fields the tunnel routes on are kept.
	tunnel           string
	upgrade          string
	connection       string
	authorization    string
	transferEncoding string
	contentLength    string
	seenFields       uint8
}

// field returns the slot for a lower-case header name the tunnel cares about, plus its "seen" bit.
func (r *tunnelRequest) field(name []byte) (*string, uint8) {
	switch string(name) {
	case "x-sudoku-tunnel":
		return &r.tunnel, 1 << 0
	case "upgrade":
		return &r.upgrade, 1 << 1
	case "connection":
		return &r.connection, 1 << 2
	case "authorization":
		return &r.authorization, 1 << 3
	case "transfer-encoding":
		return &r.transferEncoding, 1 << 4
	case "content-length":
		return &r.contentLength, 1 << 5
	}
	return nil, 0
}

func (r *tunnelRequest) setField(key, value []byte) {
	// Tunnel header names are short ASCII, so lower-casing on the stack avoids an allocation per header line.
	var stack [48]byte
	lower := append(stack[:0], key...)
	for i, c := range lower {
		if c >= 0x80 {
			lower = []byte(strings.ToLower(string(key)))
			break
		}
		if 'A' <= c && c <= 'Z' {
			lower[i] = c + 'a' - 'A'
		}
	}
	slot, bit := r.field(lower)
	if slot == nil || r.seenFields&bit != 0 {
		return
	}
	r.seenFields |= bit
	*slot = strings.TrimSpace(string(value))
}

func (r *tunnelRequest) isWebSocketUpgrade() bool {
	if !strings.EqualFold(r.upgrade, "websocket") {
		return false
	}
	for _, part := range strings.Split(r.connection, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
			return true
		}
	}
	return false
}

// buffered returns the bytes already read past the header. They are only valid until the body is read.
func (r *tunnelRequest) buffered() []byte {
	b, _ := r.br.Peek(r.br.Buffered())
	return b
}

// replayPrefix returns the request exactly as received so far. Call it only before the body is consumed.
func (r *tunnelRequest) replayPrefix() []byte {
	buffered := r.buffered()
	out := make([]byte, 0, len(r.headerBytes)+len(buffered))
	out = append(out, r.headerBytes...)
	return append(out, buffered...)
}

// body returns a reader over the request body, which follows the header in br, and its declared length (-1 when
// unknown).
func (r *tunnelRequest) body() (io.Reader, int64, error) {
	if strings.Contains(strings.ToLower(r.transferEncoding), "chunked") {
		return httputil.NewChunkedReader(r.br), -1, nil
	}
	if r.contentLength != "" {
		n, err := strconv.ParseInt(r.contentLength, 10, 64)
		if err != nil || n < 0 {
			return nil, 0, fmt.Errorf("invalid content-length")
		}
		return io.LimitReader(r.br, n), n, nil
	}
	return r.br, -1, nil
}

// readHTTPRequest parses a request header from br (which already holds first, the sniffed leading bytes). On
// failure the second result is everything read so far, ready to be replayed to the next protocol handler.
func readHTTPRequest(conn net.Conn, br *bufio.Reader, first []byte) (*tunnelRequest, []byte, error) {
	consumed := make([]byte, 0, headerBytesSizeHint)
	fail := func(err error) (*tunnelRequest, []byte, error) {
		return nil, buildInvalidHTTPReplayPrefix(first, consumed, readAllBuffered(br)), err
	}
	readLine := func() ([]byte, error) {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			if len(consumed)+len(line) > maxHTTPHeaderBytes {
				return line, fmt.Errorf("http header too large")
			}
			consumed = append(consumed, line...)
		}
		return line, err
	}

	line, err := readLine()
	if err != nil {
		return fail(err)
	}
	requestLine := strings.TrimRight(string(line), "\r\n")
	method, rest, ok := strings.Cut(requestLine, " ")
	if !ok {
		return fail(fmt.Errorf("invalid request line"))
	}
	target, proto, ok := strings.Cut(rest, " ")
	if !ok {
		return fail(fmt.Errorf("invalid request line"))
	}
	req := &tunnelRequest{conn: conn, br: br, method: method, target: target, proto: proto}

	for {
		line, err = readLine()
		if err != nil {
			return fail(err)
		}
		line = bytes.TrimRight(line, "\r\n")
		if len(line) == 0 {
			break
		}
		key, value, ok := bytes.Cut(line, []byte{':'})
		if !ok {
			continue
		}
		if key = bytes.TrimSpace(key); len(key) > 0 {
			req.setField(key, value)
		}
	}
	req.headerBytes = consumed
	return req, nil, nil
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
	buf      []byte
	recorded []byte
	rejected bool
}

func (p *preBufferedConn) CloseWrite() error {
	if p == nil {
		return nil
	}
	return tryCloseWrite(p.Conn)
}

func (p *preBufferedConn) CloseRead() error {
	if p == nil {
		return nil
	}
	return tryCloseRead(p.Conn)
}

func newPreBufferedConn(conn net.Conn, pre []byte) *preBufferedConn {
	cpy := make([]byte, len(pre))
	copy(cpy, pre)
	return &preBufferedConn{Conn: conn, buf: cpy, recorded: cpy}
}

func newRejectedPreBufferedConn(conn net.Conn, pre []byte) *preBufferedConn {
	c := newPreBufferedConn(conn, pre)
	c.rejected = true
	return c
}

func (p *preBufferedConn) IsHTTPMaskRejected() bool { return p.rejected }

func (p *preBufferedConn) GetBufferedAndRecorded() []byte {
	if len(p.recorded) == 0 {
		return nil
	}
	out := make([]byte, len(p.recorded))
	copy(out, p.recorded)
	return out
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

func (c *bodyConn) CloseWrite() error {
	if c == nil {
		return nil
	}

	var firstErr error
	if c.writer != nil {
		if err := c.writer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		// NewChunkedWriter does not write the final CRLF. Ensure a clean terminator.
		if c.tail != nil {
			_, _ = c.tail.Write([]byte("\r\n"))
		} else if c.Conn != nil {
			_, _ = c.Conn.Write([]byte("\r\n"))
		}
		if c.flush != nil {
			_ = c.flush()
		}
		c.writer = nil
	}

	if c.Conn != nil {
		if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
			if err := cw.CloseWrite(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (c *bodyConn) CloseRead() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
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

// rejectOrRespond answers a rejected request with the given status, or replays it for pass-through fallback.
// It must run before the request body is consumed.
func (s *TunnelServer) rejectOrRespond(req *tunnelRequest, code int, body string) (HandleResult, net.Conn, error) {
	if s.passThroughOnReject {
		return HandlePassThrough, newRejectedPreBufferedConn(req.conn, req.replayPrefix()), nil
	}
	return replyDone(req.conn, code, body)
}

// handleSession serves one stream or poll request. The two modes share their
// routing and differ only in payload encoding (codec) and in a few rejection
// details that older clients and probes can observe, so those are preserved.
func (s *TunnelServer) handleSession(req *tunnelRequest, codec sessionCodec) (HandleResult, net.Conn, error) {
	reject := func(code int, body string) (HandleResult, net.Conn, error) {
		return s.rejectOrRespond(req, code, body)
	}

	u, err := url.ParseRequestURI(req.target)
	if err != nil {
		return reject(http.StatusBadRequest, "bad request")
	}
	// Only accept plausible paths to reduce accidental exposure.
	path, ok := stripPathRoot(s.pathRoot, u.Path)
	if !ok || !s.isAllowedBasePath(path) {
		return reject(http.StatusNotFound, "not found")
	}
	query := u.Query()
	token := query.Get("token")

	switch strings.ToUpper(req.method) {
	case http.MethodGet:
		if token == "" && path == "/session" {
			earlyPayload, err := parseEarlyDataQuery(query)
			if err != nil {
				return reject(http.StatusBadRequest, "bad request")
			}
			return s.sessionAuthorize(req, earlyPayload)
		}
		// A tokenless pull is a bare 400 in stream mode but reaches the session
		// lookup (403) in poll mode.
		if path != "/stream" || (token == "" && !codec.poll) {
			return reject(http.StatusBadRequest, "bad request")
		}
		if s.passThroughOnReject && !s.sessionHas(token) {
			return reject(http.StatusNotFound, "not found")
		}
		return s.pull(req.conn, token, codec)

	case http.MethodPost:
		if path == "/api/v1/upload" && token != "" {
			return s.handleUpload(req, query, codec)
		}
		if codec.poll {
			if path != "/api/v1/upload" {
				return reject(http.StatusBadRequest, "bad request")
			}
			return reject(http.StatusBadRequest, "missing token")
		}
		return s.startStreamOne(req)

	default:
		return reject(http.StatusBadRequest, "bad request")
	}
}

// handleUpload serves POST <root>/api/v1/upload?token=...: close, FIN or a payload push.
func (s *TunnelServer) handleUpload(req *tunnelRequest, query url.Values, codec sessionCodec) (HandleResult, net.Conn, error) {
	rawConn := req.conn
	token := query.Get("token")

	if query.Get("close") == "1" {
		s.sessionClose(token)
		return replyDone(rawConn, http.StatusOK, "")
	}
	if query.Get("fin") == "1" {
		s.sessionCloseWrite(token)
		return replyDone(rawConn, http.StatusOK, "")
	}
	if s.passThroughOnReject && !s.sessionHas(token) {
		return s.rejectOrRespond(req, http.StatusNotFound, "not found")
	}
	body, length, err := req.body()
	if err != nil {
		if codec.poll {
			return s.rejectOrRespond(req, http.StatusBadRequest, "bad request")
		}
		return replyDone(rawConn, http.StatusBadRequest, "bad request")
	}
	sequence, err := parseUploadSequence(query)
	if err != nil {
		return s.rejectOrRespond(req, http.StatusBadRequest, "bad request")
	}
	return s.push(rawConn, token, sequence, body, length, codec)
}

// startStreamOne turns a tokenless POST into a single full-duplex tunnel.
func (s *TunnelServer) startStreamOne(req *tunnelRequest) (HandleResult, net.Conn, error) {
	rawConn := req.conn
	if err := writeTunnelResponseHeader(rawConn); err != nil {
		_ = rawConn.Close()
		return HandleDone, nil, err
	}
	bodyReader, _, err := req.body()
	if err != nil {
		_ = rawConn.Close()
		return HandleDone, nil, err
	}

	bw := bufio.NewWriterSize(rawConn, 32*1024)
	return HandleStartTunnel, &bodyConn{
		Conn:   rawConn,
		reader: bodyReader,
		writer: httputil.NewChunkedWriter(bw),
		tail:   bw,
		flush:  bw.Flush,
	}, nil
}

func (s *TunnelServer) isAllowedBasePath(path string) bool {
	for _, p := range paths {
		if path == p {
			return true
		}
	}
	return false
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

func writeSessionPullResponseHeader(w io.Writer) error {
	_, err := io.WriteString(w,
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Trailer: "+tunnelStreamEOFHeader+"\r\n"+
			"Cache-Control: no-store\r\n"+
			"Pragma: no-cache\r\n"+
			"Connection: keep-alive\r\n"+
			"X-Accel-Buffering: no\r\n"+
			"\r\n")
	return err
}

// replyDone answers a one-shot request and ends handling of the connection.
func replyDone(rawConn net.Conn, code int, body string) (HandleResult, net.Conn, error) {
	_ = writeSimpleHTTPResponse(rawConn, code, body)
	_ = rawConn.Close()
	return HandleDone, nil, nil
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

func writeTokenHTTPResponse(w io.Writer, token string, earlyPayload []byte) error {
	token = strings.TrimRight(token, "\r\n")
	body := "token=" + token
	if len(earlyPayload) > 0 {
		body += "\ned=" + base64.RawURLEncoding.EncodeToString(earlyPayload)
	}
	body += "\ncap=" + tunnelUploadSequenceCap
	// Use application/octet-stream to avoid CDN auto-compression (e.g. brotli) breaking clients that expect a plain token string.
	_, err := io.WriteString(w,
		fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nPragma: no-cache\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(body), body))
	return err
}

func (s *TunnelServer) sessionAuthorize(req *tunnelRequest, earlyPayload []byte) (HandleResult, net.Conn, error) {
	rawConn := req.conn
	token, err := newSessionToken()
	if err != nil {
		return replyDone(rawConn, http.StatusInternalServerError, "internal error")
	}

	c1, c2 := newHalfPipe()
	outConn := net.Conn(c1)
	var responsePayload []byte
	var userHash string
	if len(earlyPayload) > 0 && s.earlyHandshake != nil && s.earlyHandshake.Prepare != nil {
		prepared, err := s.earlyHandshake.Prepare(earlyPayload)
		if err != nil {
			_ = c1.Close()
			_ = c2.Close()
			return s.rejectOrRespond(req, http.StatusNotFound, "not found")
		}
		responsePayload = prepared.ResponsePayload
		userHash = prepared.UserHash
		if prepared.WrapConn != nil {
			wrapped, err := prepared.WrapConn(c1)
			if err != nil {
				_ = c1.Close()
				_ = c2.Close()
				return replyDone(rawConn, http.StatusInternalServerError, "internal error")
			}
			if wrapped != nil {
				outConn = wrapEarlyHandshakeConn(wrapped, userHash)
			}
		}
	}

	s.sessionAdd(token, c2)

	if err := writeTokenHTTPResponse(rawConn, token, responsePayload); err != nil {
		s.sessionClose(token)
		_ = rawConn.Close()
		return HandleDone, nil, err
	}
	_ = rawConn.Close()
	return HandleStartTunnel, outConn, nil
}

func newSessionToken() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// sessionAdd registers a session for conn and arms its idle reaper.
func (s *TunnelServer) sessionAdd(token string, conn *halfPipeConn) *tunnelSession {
	sess := &tunnelSession{conn: conn, lastActive: time.Now(), nextUploadSeq: 1}
	s.mu.Lock()
	s.sessions[token] = sess
	sess.reaper = time.AfterFunc(s.sessionTTL, func() { s.reap(token, sess) })
	s.mu.Unlock()
	return sess
}

// shutdown disarms the reaper, stops the active pull and closes the tunnel pipe.
func (sess *tunnelSession) shutdown() {
	sess.reaper.Stop()
	sess.pullMu.Lock()
	lease := sess.pull
	sess.pullMu.Unlock()
	lease.stop()
	_ = sess.conn.Close()
}

// reap runs when the reaper fires and re-arms it unless sess is gone.
func (s *TunnelServer) reap(token string, sess *tunnelSession) {
	next, done := s.reapIfIdle(token, sess)
	if done {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[token] == sess {
		// Best-effort cleanup does not need a tight loop under constant activity.
		if next < minReapInterval {
			next = minReapInterval
		}
		sess.reaper.Reset(next)
	}
}

// reapIfIdle closes sess once it has been idle for the TTL with no active pull,
// otherwise it returns how long to wait before checking again.
func (s *TunnelServer) reapIfIdle(token string, sess *tunnelSession) (next time.Duration, done bool) {
	s.mu.Lock()
	if s.sessions[token] != sess {
		s.mu.Unlock()
		return 0, true
	}
	idle := time.Since(sess.lastActive)
	s.mu.Unlock()

	// Pull ownership has its own lock. Do not take it while holding s.mu:
	// pull takeover validates the session while holding pullMu.
	sess.pullMu.Lock()
	pulling := sess.pull != nil
	sess.pullMu.Unlock()

	s.mu.Lock()
	if s.sessions[token] != sess {
		s.mu.Unlock()
		return 0, true
	}
	if idle >= s.sessionTTL && !pulling {
		delete(s.sessions, token)
		s.mu.Unlock()
		sess.shutdown()
		return 0, true
	}
	next = s.sessionTTL - idle
	if pulling && next < s.sessionTTL {
		next = s.sessionTTL
	}
	s.mu.Unlock()
	return next, false
}

func (s *TunnelServer) sessionHas(token string) bool {
	s.mu.Lock()
	_, ok := s.sessions[token]
	s.mu.Unlock()
	return ok
}

func (s *TunnelServer) sessionGet(token string) (*tunnelSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	sess.lastActive = time.Now()
	return sess, true
}

func (s *TunnelServer) sessionTouch(token string, sess *tunnelSession) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[token]
	if !ok || current != sess {
		return false
	}
	sess.lastActive = time.Now()
	return true
}

func (s *TunnelServer) sessionClose(token string) {
	s.mu.Lock()
	sess, ok := s.sessions[token]
	if ok {
		delete(s.sessions, token)
	}
	s.mu.Unlock()
	if ok {
		sess.shutdown()
	}
}

func (s *TunnelServer) sessionCloseWrite(token string) {
	s.sessionHalfClose(token, sessionUplink)
}

func (s *TunnelServer) sessionHalfClose(token string, direction sessionDirection) {
	var closeWrite, removed bool

	s.mu.Lock()
	sess, ok := s.sessions[token]
	if !ok {
		s.mu.Unlock()
		return
	}
	sess.lastActive = time.Now()
	switch direction {
	case sessionUplink:
		if !sess.uplinkClosed {
			sess.uplinkClosed = true
			closeWrite = true
		}
	case sessionDownlink:
		sess.downlinkClosed = true
	}
	if sess.uplinkClosed && sess.downlinkClosed {
		delete(s.sessions, token)
		removed = true
	}
	s.mu.Unlock()

	if closeWrite {
		_ = tryCloseWrite(sess.conn)
	}
	// When both directions are complete the session has been removed. Closing
	// the backing connection is safe after the optional half-close above and
	// prevents a leaked pipe from surviving its token.
	if removed {
		sess.reaper.Stop()
		_ = sess.conn.Close()
	}
}

func parseUploadSequence(query url.Values) (uint64, error) {
	raw := strings.TrimSpace(query.Get(tunnelUploadSequenceQuery))
	if raw == "" {
		return 0, errors.New("missing upload sequence")
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 {
		return 0, errors.New("invalid upload sequence")
	}
	return value, nil
}

func (s *TunnelServer) writeSessionUpload(token string, sess *tunnelSession, sequence uint64, payload []byte) error {
	sess.uploadMu.Lock()
	defer sess.uploadMu.Unlock()

	if !s.sessionTouch(token, sess) {
		return net.ErrClosed
	}
	switch {
	case sequence < sess.nextUploadSeq:
		// The previous request reached the server but its HTTP response was
		// lost. Treat the retried batch as an acknowledged no-op.
		return nil
	case sequence > sess.nextUploadSeq:
		return errUploadSequenceGap
	}

	if len(payload) > 0 {
		_ = sess.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		err := writeFull(sess.conn, payload)
		_ = sess.conn.SetWriteDeadline(time.Time{})
		if err != nil {
			return err
		}
	}
	sess.nextUploadSeq++
	return nil
}

const (
	maxUploadBytes = 1 << 20 // per request
	// presizedUploadBytes bounds how much of a declared Content-Length is allocated before any byte arrives; it
	// matches the largest batch a stream client sends.
	presizedUploadBytes = 256 << 10
)

// readUpload reads up to limit bytes of r into a pooled buffer. length is the declared body size, or -1 when
// unknown. The caller returns the buffer with pool.Put once the bytes are consumed, also when err is not nil.
func readUpload(r io.Reader, length int64, limit int) ([]byte, error) {
	size := 4096
	if length >= 0 {
		// One spare byte lets the final Read report EOF without growing the buffer.
		size = presizedUploadBytes
		if length < int64(size) {
			size = int(length)
		}
		size++
	}
	buf := pool.Get(size)[:0]
	for len(buf) < limit {
		if len(buf) == cap(buf) {
			grown := pool.Get(2 * cap(buf))
			grown = grown[:copy(grown, buf)]
			_ = pool.Put(buf)
			buf = grown
		}
		end := cap(buf)
		if end > limit {
			end = limit
		}
		n, err := r.Read(buf[len(buf):end])
		buf = buf[:len(buf)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return buf, err
		}
	}
	return buf, nil
}

// decodeUploadLines base64-decodes every non-blank line of encoded and concatenates the results in a pooled
// buffer that the caller returns with pool.Put.
func decodeUploadLines(encoded []byte) ([]byte, error) {
	out := pool.Get(base64.StdEncoding.DecodedLen(len(encoded)))[:0]
	for len(encoded) > 0 {
		var line []byte
		line, encoded, _ = bytes.Cut(encoded, []byte{'\n'})
		if line = bytes.TrimSpace(line); len(line) == 0 {
			continue
		}
		n, err := base64.StdEncoding.Decode(out[len(out):cap(out)], line)
		if err != nil {
			return out, err
		}
		out = out[:len(out)+n]
	}
	return out, nil
}

func writeUploadResult(rawConn net.Conn, err error) (HandleResult, net.Conn, error) {
	if errors.Is(err, errUploadSequenceGap) {
		return replyDone(rawConn, http.StatusConflict, "sequence gap")
	}
	return replyDone(rawConn, http.StatusGone, "gone")
}

// readUpload reads one upload body of the given declared length (-1 when unknown) and returns the tunnel bytes it
// carries in a pooled buffer. The caller returns the buffer with pool.Put also when err is not nil.
func (c sessionCodec) readUpload(body io.Reader, length int64) ([]byte, error) {
	if !c.poll {
		payload, err := readUpload(body, length, maxUploadBytes+1)
		if err == nil && len(payload) > maxUploadBytes {
			err = errUploadTooLarge
		}
		return payload, err
	}

	encoded, err := readUpload(body, length, maxUploadBytes)
	defer func() { _ = pool.Put(encoded) }()
	if err != nil {
		return nil, err
	}
	return decodeUploadLines(encoded)
}

// push applies one upload request to the session and answers it.
func (s *TunnelServer) push(rawConn net.Conn, token string, sequence uint64, body io.Reader, length int64, codec sessionCodec) (HandleResult, net.Conn, error) {
	sess, ok := s.sessionGet(token)
	if !ok {
		return replyDone(rawConn, http.StatusForbidden, "forbidden")
	}

	payload, err := codec.readUpload(body, length)
	defer func() { _ = pool.Put(payload) }()
	if errors.Is(err, errUploadTooLarge) {
		return replyDone(rawConn, http.StatusRequestEntityTooLarge, "too large")
	}
	if err != nil {
		return replyDone(rawConn, http.StatusBadRequest, "bad request")
	}

	if err := s.writeSessionUpload(token, sess, sequence, payload); err != nil {
		if !errors.Is(err, errUploadSequenceGap) {
			s.sessionClose(token)
		}
		return writeUploadResult(rawConn, err)
	}
	return replyDone(rawConn, http.StatusOK, "")
}

func (s *TunnelServer) beginSessionPull(token string, sess *tunnelSession, rawConn net.Conn) (*sessionPullLease, bool) {
	for {
		sess.pullMu.Lock()
		if !s.sessionTouch(token, sess) {
			sess.pullMu.Unlock()
			return nil, false
		}
		previous := sess.pull
		if previous == nil {
			lease := newSessionPullLease(rawConn)
			sess.pull = lease
			sess.pullMu.Unlock()
			return lease, true
		}
		previous.stop()
		sess.pullMu.Unlock()

		// Only one goroutine may read a session pipe. A new pull takes over a
		// stale CDN response by waking its pending read before it starts.
		_ = sess.conn.SetReadDeadline(time.Now())
		<-previous.done
	}
}

func (s *TunnelServer) endSessionPull(token string, sess *tunnelSession, lease *sessionPullLease) {
	if lease == nil {
		return
	}
	sess.pullMu.Lock()
	if sess.pull == lease {
		sess.pull = nil
	}
	sess.pullMu.Unlock()
	close(lease.done)
}

// pull answers GET <root>/stream with a chunked downlink until the session has
// nothing more to say, the response breaks or another pull takes over.
func (s *TunnelServer) pull(rawConn net.Conn, token string, codec sessionCodec) (HandleResult, net.Conn, error) {
	sess, ok := s.sessionGet(token)
	if !ok {
		return replyDone(rawConn, http.StatusForbidden, "forbidden")
	}

	lease, ok := s.beginSessionPull(token, sess, rawConn)
	if !ok {
		return replyDone(rawConn, http.StatusForbidden, "forbidden")
	}
	defer s.endSessionPull(token, sess, lease)

	if err := writeSessionPullResponseHeader(rawConn); err != nil {
		_ = rawConn.Close()
		return HandleDone, nil, err
	}

	// nil once a frame failed to go out whole: the body is already broken, so no terminator.
	end := pullEnd
	defer func() {
		if end != nil {
			_, _ = rawConn.Write(end)
		}
		_ = rawConn.Close()
	}()

	for {
		select {
		case <-lease.cancel:
			return HandleDone, nil, nil
		default:
		}

		// An idle pull waits for the tunnel without holding a buffer; one is taken only once bytes arrive.
		payload := sess.pendingDownlink
		var read []byte
		var readErr error
		if len(payload) == 0 {
			_ = sess.conn.SetReadDeadline(time.Now().Add(s.pullReadTimeout))
			if readErr = sess.conn.awaitReadable(); readErr == nil {
				read = pool.Get(downlinkReadBytes)
				var n int
				n, readErr = sess.conn.Read(read)
				payload = read[:n]
			}
		}
		if len(payload) > 0 {
			if !s.sessionTouch(token, sess) {
				_ = pool.Put(read)
				return HandleDone, nil, nil
			}
			frame := codec.appendPullFrame(pool.Get(codec.pullFrameSize(len(payload)))[:0], payload)
			_ = rawConn.SetWriteDeadline(time.Now().Add(s.pullReadTimeout))
			err := writeFull(rawConn, frame)
			_ = pool.Put(frame)
			if err != nil {
				// The HTTP response may be reset by a CDN while the backing
				// tunnel is still healthy. The client will establish a fresh
				// pull request, so never destroy the session for this request's
				// downstream socket failure; its next pull resends the payload.
				sess.pendingDownlink = append(sess.pendingDownlink[:0], payload...)
				_ = pool.Put(read)
				end = nil
				return HandleDone, nil, nil
			}
			_ = rawConn.SetWriteDeadline(time.Time{})
			sess.pendingDownlink = nil
		}
		_ = pool.Put(read)
		if readErr == nil {
			continue
		}

		switch {
		case errors.Is(readErr, os.ErrDeadlineExceeded):
			select {
			case <-lease.cancel:
			default:
				if codec.poll {
					end = pollKeepaliveEnd
					s.sessionTouch(token, sess)
				}
			}
		case errors.Is(readErr, io.EOF):
			end = pullEndAfterEOF
			s.sessionHalfClose(token, sessionDownlink)
		default:
			s.sessionClose(token)
		}
		return HandleDone, nil, nil
	}
}

// sessionCodec is how a mode carries tunnel bytes: raw octets for stream, one
// base64 line per payload for poll.
type sessionCodec struct {
	poll bool
}

var (
	streamCodec = sessionCodec{}
	pollCodec   = sessionCodec{poll: true}
)

const (
	downlinkReadBytes = 32 * 1024

	// pollNewlineChunk is the one-byte chunk that ends every poll line and doubles as the idle keepalive.
	pollNewlineChunk = "1\r\n\n\r\n"
)

// Bodies end with the zero chunk; EOF is reported as a trailer, which is why the response header announces one.
var (
	pullEnd          = []byte("0\r\n\r\n")
	pullEndAfterEOF  = []byte("0\r\n" + tunnelStreamEOFHeader + ": 1\r\n\r\n")
	pollKeepaliveEnd = []byte(pollNewlineChunk + "0\r\n\r\n")
)

// pullFrameSize bounds the chunked-body bytes that carry an n-byte downlink payload.
func (c sessionCodec) pullFrameSize(n int) int {
	if c.poll {
		return 8 + base64.StdEncoding.EncodedLen(n) + len(pollNewlineChunk)
	}
	return 8 + n
}

// appendPullFrame appends the chunked-body bytes that carry one downlink payload: a single chunk of raw octets for
// stream, a base64 line chunk followed by a newline chunk for poll.
func (c sessionCodec) appendPullFrame(dst, payload []byte) []byte {
	if !c.poll {
		return appendChunk(dst, payload)
	}
	encLen := base64.StdEncoding.EncodedLen(len(payload))
	dst = strconv.AppendInt(dst, int64(encLen), 16)
	dst = append(dst, '\r', '\n')
	start := len(dst)
	dst = dst[:start+encLen]
	base64.StdEncoding.Encode(dst[start:], payload)
	dst = append(dst, '\r', '\n')
	return append(dst, pollNewlineChunk...)
}

func appendChunk(dst, data []byte) []byte {
	dst = strconv.AppendInt(dst, int64(len(data)), 16)
	dst = append(dst, '\r', '\n')
	dst = append(dst, data...)
	return append(dst, '\r', '\n')
}
