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
	Path        string
	Host        string
	Mode        string
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
	uploadQueue *uploadQueue
	connected   chan struct{}
	once        sync.Once
}

func newHTTPSession() *httpSession {
	return &httpSession{
		uploadQueue: NewUploadQueue(),
		connected:   make(chan struct{}),
	}
}

func (s *httpSession) markConnected() {
	s.once.Do(func() {
		close(s.connected)
	})
}

type requestHandler struct {
	path        string
	host        string
	mode        string
	connHandler func(net.Conn)
	httpHandler http.Handler

	mu       sync.Mutex
	sessions map[string]*httpSession
}

func NewServerHandler(opt ServerOption) http.Handler {
	path := opt.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// using h2c.NewHandler to ensure we can work in plain http2
	// and some tls conn is not *tls.Conn (like *reality.Conn)
	return h2c.NewHandler(&requestHandler{
		path:        path,
		host:        opt.Host,
		mode:        opt.Mode,
		connHandler: opt.ConnHandler,
		httpHandler: opt.HttpHandler,
		sessions:    map[string]*httpSession{},
	}, &http.Http2Server{
		IdleTimeout: 30 * time.Second,
	})
}

func (h *requestHandler) getOrCreateSession(sessionID string) *httpSession {
	h.mu.Lock()
	defer h.mu.Unlock()

	s, ok := h.sessions[sessionID]
	if ok {
		return s
	}

	s = newHTTPSession()
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

func (h *requestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.httpHandler != nil && !strings.HasPrefix(r.URL.Path, h.path) {
		h.httpHandler.ServeHTTP(w, r)
		return
	}

	if h.host != "" && !equalHost(r.Host, h.host) {
		http.NotFound(w, r)
		return
	}

	if !strings.HasPrefix(r.URL.Path, h.path) {
		http.NotFound(w, r)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, h.path)
	parts := splitNonEmpty(rest)

	// stream-one: POST /path
	if r.Method == http.MethodPost && len(parts) == 0 {
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

	// packet-up download: GET /path/{session}
	if r.Method == http.MethodGet && len(parts) == 1 {
		sessionID := parts[0]
		session := h.getOrCreateSession(sessionID)
		session.markConnected()

		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-store")
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
	if r.Method == http.MethodPost && len(parts) == 1 {
		sessionID := parts[0]
		session := h.getSession(sessionID)
		if session == nil {
			http.Error(w, "unknown xhttp session", http.StatusBadRequest)
			return
		}

		buf := make([]byte, 32*1024)
		var seq uint64

		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if pushErr := session.uploadQueue.Push(Packet{
					Seq:     seq,
					Payload: buf[:n],
				}); pushErr != nil {
					http.Error(w, pushErr.Error(), http.StatusInternalServerError)
					return
				}
				seq++
			}

			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		return
	}

	// packet-up upload: POST /path/{session}/{seq}
	if r.Method == http.MethodPost && len(parts) == 2 {
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

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := session.uploadQueue.Push(Packet{
			Seq:     seq,
			Payload: body,
		}); err != nil {
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
