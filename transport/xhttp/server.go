package xhttp

import (
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
	N "github.com/metacubex/mihomo/common/net"

	"github.com/metacubex/http"
	"github.com/metacubex/http/h2c"
)

type ServerOption struct {
	Config
	ConnHandler func(net.Conn)
	HttpHandler http.Handler
}

type httpServerConn struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher
	reader  io.Reader
	closed  bool
	done    chan struct{}
	once    sync.Once
}

func newHTTPServerConn(w http.ResponseWriter, r io.Reader) *httpServerConn {
	flusher, _ := w.(http.Flusher)
	return &httpServerConn{
		w:       w,
		flusher: flusher,
		reader:  r,
		done:    make(chan struct{}),
	}
}

func (c *httpServerConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, io.ErrClosedPipe
	}

	n, err := c.w.Write(b)
	if err == nil && c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.done)
	})
	return nil
}

func (c *httpServerConn) Wait() <-chan struct{} {
	return c.done
}

type httpSession struct {
	uploadQueue *UploadQueue
	connected   chan struct{}
	once        sync.Once
}

func newHTTPSession(maxPackets int) *httpSession {
	return &httpSession{
		uploadQueue: NewUploadQueue(maxPackets),
		connected:   make(chan struct{}),
	}
}

func (s *httpSession) markConnected() {
	s.once.Do(func() {
		close(s.connected)
	})
}

type requestHandler struct {
	config      Config
	connHandler func(net.Conn)
	httpHandler http.Handler

	scMaxEachPostBytes   Range
	scStreamUpServerSecs Range
	scMaxBufferedPosts   Range

	mu       sync.Mutex
	sessions map[string]*httpSession
}

func NewServerHandler(opt ServerOption) (http.Handler, error) {
	scMaxEachPostBytes, err := opt.Config.GetNormalizedScMaxEachPostBytes()
	if err != nil {
		return nil, err
	}
	scStreamUpServerSecs, err := opt.Config.GetNormalizedScStreamUpServerSecs()
	if err != nil {
		return nil, err
	}
	scMaxBufferedPosts, err := opt.Config.GetNormalizedScMaxBufferedPosts()
	if err != nil {
		return nil, err
	}
	// using h2c.NewHandler to ensure we can work in plain http2
	// and some tls conn is not *tls.Conn (like *reality.Conn)
	return h2c.NewHandler(&requestHandler{
		config:               opt.Config,
		connHandler:          opt.ConnHandler,
		httpHandler:          opt.HttpHandler,
		scMaxEachPostBytes:   scMaxEachPostBytes,
		scStreamUpServerSecs: scStreamUpServerSecs,
		scMaxBufferedPosts:   scMaxBufferedPosts,
		sessions:             map[string]*httpSession{},
	}, &http.Http2Server{
		IdleTimeout: 30 * time.Second,
	}), nil
}

func (h *requestHandler) getOrCreateSession(sessionID string) *httpSession {
	h.mu.Lock()
	defer h.mu.Unlock()

	s, ok := h.sessions[sessionID]
	if ok {
		return s
	}

	s = newHTTPSession(h.scMaxBufferedPosts.Max)
	h.sessions[sessionID] = s
	return s
}

func (h *requestHandler) deleteSession(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if s, ok := h.sessions[sessionID]; ok {
		_ = s.uploadQueue.Close()
		delete(h.sessions, sessionID)
	}
}

func (h *requestHandler) getSession(sessionID string) *httpSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[sessionID]
}

func (h *requestHandler) normalizedMode() string {
	if h.config.Mode == "" {
		return "auto"
	}
	return h.config.Mode
}

func (h *requestHandler) allowStreamOne() bool {
	switch h.normalizedMode() {
	case "auto", "stream-one", "stream-up":
		return true
	default:
		return false
	}
}

func (h *requestHandler) allowSessionDownload() bool {
	switch h.normalizedMode() {
	case "auto", "stream-up", "packet-up":
		return true
	default:
		return false
	}
}

func (h *requestHandler) allowStreamUpUpload() bool {
	switch h.normalizedMode() {
	case "auto", "stream-up":
		return true
	default:
		return false
	}
}

func (h *requestHandler) allowPacketUpUpload() bool {
	switch h.normalizedMode() {
	case "auto", "packet-up":
		return true
	default:
		return false
	}
}

func (h *requestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := h.config.NormalizedPath()
	if h.httpHandler != nil && !strings.HasPrefix(r.URL.Path, path) {
		h.httpHandler.ServeHTTP(w, r)
		return
	}

	if h.config.Host != "" && !equalHost(r.Host, h.config.Host) {
		http.NotFound(w, r)
		return
	}

	if !strings.HasPrefix(r.URL.Path, path) {
		http.NotFound(w, r)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, path)
	parts := splitNonEmpty(rest)

	// stream-one: POST /path
	if r.Method == http.MethodPost && len(parts) == 0 && h.allowStreamOne() {
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		httpSC := newHTTPServerConn(w, r.Body)
		conn := &Conn{
			writer: httpSC,
			reader: httpSC,
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, r)

		go h.connHandler(N.NewDeadlineConn(conn))

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = conn.Close()
		return
	}

	// stream-up/packet-up download: GET /path/{session}
	if r.Method == http.MethodGet && len(parts) == 1 && h.allowSessionDownload() {
		sessionID := parts[0]
		session := h.getOrCreateSession(sessionID)
		session.markConnected()

		// magic header instructs nginx + apache to not buffer response body
		w.Header().Set("X-Accel-Buffering", "no")
		// A web-compliant header telling all middleboxes to disable caching.
		// Should be able to prevent overloading the cache, or stop CDNs from
		// teeing the response stream into their cache, causing slowdowns.
		w.Header().Set("Cache-Control", "no-store")
		if !h.config.NoSSEHeader {
			// magic header to make the HTTP middle box consider this as SSE to disable buffer
			w.Header().Set("Content-Type", "text/event-stream")
		}
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		httpSC := newHTTPServerConn(w, r.Body)
		conn := &Conn{
			writer: httpSC,
			reader: session.uploadQueue,
			onClose: func() {
				h.deleteSession(sessionID)
			},
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, r)

		go h.connHandler(N.NewDeadlineConn(conn))

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = conn.Close()
		return
	}

	// stream-up upload: POST /path/{session}
	if r.Method == http.MethodPost && len(parts) == 1 && h.allowStreamUpUpload() {
		sessionID := parts[0]
		session := h.getSession(sessionID)
		if session == nil {
			http.Error(w, "unknown xhttp session", http.StatusBadRequest)
			return
		}

		httpSC := newHTTPServerConn(w, r.Body)
		err := session.uploadQueue.Push(Packet{
			Reader: httpSC,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// magic header instructs nginx + apache to not buffer response body
		w.Header().Set("X-Accel-Buffering", "no")
		// A web-compliant header telling all middleboxes to disable caching.
		// Should be able to prevent overloading the cache, or stop CDNs from
		// teeing the response stream into their cache, causing slowdowns.
		w.Header().Set("Cache-Control", "no-store")
		if !h.config.NoSSEHeader {
			// magic header to make the HTTP middle box consider this as SSE to disable buffer
			w.Header().Set("Content-Type", "text/event-stream")
		}
		w.WriteHeader(http.StatusOK)
		referrer := r.Header.Get("Referer")
		if referrer != "" && h.scStreamUpServerSecs.Max > 0 {
			go func() {
				for {
					paddingValue, _ := h.config.RandomPadding()
					if paddingValue == "" {
						break
					}
					_, err = httpSC.Write([]byte(paddingValue))
					if err != nil {
						break
					}
					time.Sleep(time.Duration(h.scStreamUpServerSecs.Rand()) * time.Second)
				}
			}()
		}

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = httpSC.Close()
		return
	}

	// packet-up upload: POST /path/{session}/{seq}
	if r.Method == http.MethodPost && len(parts) == 2 && h.allowPacketUpUpload() {
		sessionID := parts[0]
		seq, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			http.Error(w, "invalid xhttp seq", http.StatusBadRequest)
			return
		}

		session := h.getSession(sessionID)
		if session == nil {
			http.Error(w, "unknown xhttp session", http.StatusBadRequest)
			return
		}

		if r.ContentLength > int64(h.scMaxEachPostBytes.Max) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, int64(h.scMaxEachPostBytes.Max)+1))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		err = session.uploadQueue.Push(Packet{
			Seq:     seq,
			Payload: body,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(body) == 0 {
			w.Header().Set("Cache-Control", "no-store")
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	http.NotFound(w, r)
}

func splitNonEmpty(s string) []string {
	raw := strings.Split(s, "/")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func equalHost(a, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	if ah, _, err := net.SplitHostPort(a); err == nil {
		a = ah
	}
	if bh, _, err := net.SplitHostPort(b); err == nil {
		b = bh
	}

	return a == b
}
