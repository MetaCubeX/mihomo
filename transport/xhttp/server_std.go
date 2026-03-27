package xhttp

import (
	"io"
	"net"
	nethttp "net/http"
	"strconv"
	"strings"
	"sync"
)

type stdHTTPServerConn struct {
	mu      sync.Mutex
	w       nethttp.ResponseWriter
	flusher nethttp.Flusher
	reader  io.Reader
	closed  bool
	done    chan struct{}
	once    sync.Once
}

func newStdHTTPServerConn(w nethttp.ResponseWriter, r io.Reader) *stdHTTPServerConn {
	flusher, _ := w.(nethttp.Flusher)
	return &stdHTTPServerConn{
		w:       w,
		flusher: flusher,
		reader:  r,
		done:    make(chan struct{}),
	}
}

func (c *stdHTTPServerConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *stdHTTPServerConn) Write(b []byte) (int, error) {
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

func (c *stdHTTPServerConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.done)
	})
	return nil
}

func (c *stdHTTPServerConn) Wait() <-chan struct{} {
	return c.done
}

type stdRequestHandler struct {
	path        string
	host        string
	mode        string
	connHandler func(net.Conn)
	httpHandler nethttp.Handler

	mu       sync.Mutex
	sessions map[string]*httpSession
}

func NewStdServerHandler(opt ServerOption) nethttp.Handler {
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

	return &stdRequestHandler{
		path:        path,
		host:        opt.Host,
		mode:        opt.Mode,
		connHandler: opt.ConnHandler,
		httpHandler: nil,
		sessions:    map[string]*httpSession{},
	}
}

func (h *stdRequestHandler) getOrCreateSession(sessionID string) *httpSession {
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

func (h *stdRequestHandler) deleteSession(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if s, ok := h.sessions[sessionID]; ok {
		_ = s.uploadQueue.Close()
		delete(h.sessions, sessionID)
	}
}

func (h *stdRequestHandler) getSession(sessionID string) *httpSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[sessionID]
}

func (h *stdRequestHandler) ServeHTTP(w nethttp.ResponseWriter, r *nethttp.Request) {
	if h.host != "" && !equalHost(r.Host, h.host) {
		nethttp.NotFound(w, r)
		return
	}

	if !strings.HasPrefix(r.URL.Path, h.path) {
		nethttp.NotFound(w, r)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, h.path)
	parts := splitNonEmpty(rest)

	remoteAddr := remoteAddrFromStdRequest(r)
	localAddr := &net.TCPAddr{}

	if r.Method == nethttp.MethodPost && len(parts) == 0 {
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(nethttp.StatusOK)
		if flusher, ok := w.(nethttp.Flusher); ok {
			flusher.Flush()
		}

		httpSC := newStdHTTPServerConn(w, r.Body)
		conn := &Conn{
			writer:     httpSC,
			reader:     httpSC,
			remoteAddr: remoteAddr,
			localAddr:  localAddr,
		}

		go h.connHandler(conn)

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = conn.Close()
		return
	}

	if r.Method == nethttp.MethodGet && len(parts) == 1 {
		sessionID := parts[0]
		session := h.getOrCreateSession(sessionID)
		session.markConnected()

		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(nethttp.StatusOK)
		if flusher, ok := w.(nethttp.Flusher); ok {
			flusher.Flush()
		}

		httpSC := newStdHTTPServerConn(w, r.Body)
		conn := &Conn{
			writer:     httpSC,
			reader:     session.uploadQueue,
			remoteAddr: remoteAddr,
			localAddr:  localAddr,
			onClose: func() {
				h.deleteSession(sessionID)
			},
		}

		go h.connHandler(conn)

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = conn.Close()
		return
	}

	if r.Method == nethttp.MethodPost && len(parts) == 2 {
		sessionID := parts[0]
		seq, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			nethttp.Error(w, "invalid xhttp seq", nethttp.StatusBadRequest)
			return
		}

		session := h.getSession(sessionID)
		if session == nil {
			nethttp.Error(w, "unknown xhttp session", nethttp.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			nethttp.Error(w, err.Error(), nethttp.StatusBadRequest)
			return
		}

		if err := session.uploadQueue.Push(Packet{
			Seq:     seq,
			Payload: body,
		}); err != nil {
			nethttp.Error(w, err.Error(), nethttp.StatusInternalServerError)
			return
		}

		if len(body) == 0 {
			w.Header().Set("Cache-Control", "no-store")
		}
		w.WriteHeader(nethttp.StatusOK)
		return
	}

	nethttp.NotFound(w, r)
}

func remoteAddrFromStdRequest(r *nethttp.Request) net.Addr {
	addr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		return &net.TCPAddr{}
	}
	return addr
}
