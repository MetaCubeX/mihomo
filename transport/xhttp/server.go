package xhttp

import (
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/http"
)

type SplitHTTPServer struct {
	config    *SplitHTTPConfig
	sessionMu sync.Mutex
	sessions  sync.Map
	addConn   func(net.Conn)
}

func NewSplitHTTPServer(config *SplitHTTPConfig, addConn func(net.Conn)) *SplitHTTPServer {
	return &SplitHTTPServer{
		config:  config,
		addConn: addConn,
	}
}

type httpSession struct {
	uploadQueue      *uploadQueue
	isFullyConnected chan struct{}
	once             sync.Once
}

func (s *httpSession) fullyConnected() {
	s.once.Do(func() {
		close(s.isFullyConnected)
	})
}

func (h *SplitHTTPServer) upsertSession(sessionId string) *httpSession {
	if currentSessionAny, ok := h.sessions.Load(sessionId); ok {
		return currentSessionAny.(*httpSession)
	}

	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()

	if currentSessionAny, ok := h.sessions.Load(sessionId); ok {
		return currentSessionAny.(*httpSession)
	}

	queueSize := h.config.MaxConcurrentPosts
	if queueSize == 0 {
		queueSize = 100 // default max concurrent posts
	}
	s := &httpSession{
		uploadQueue:      NewUploadQueue(queueSize),
		isFullyConnected: make(chan struct{}),
	}

	h.sessions.Store(sessionId, s)

	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			h.sessions.Delete(sessionId)
			s.uploadQueue.Close()
		case <-s.isFullyConnected:
		}
	}()

	return s
}

func (h *SplitHTTPServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	config := h.config
	path := config.GetNormalizedPath()

	if !strings.HasPrefix(request.URL.Path, path) {
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	header := writer.Header()
	header.Set("Content-Type", "application/grpc") // basic emulation
	if paddingAuth := request.Header.Get("X-Padding"); paddingAuth != "" {
		// skip complex padding, just flush
	}

	sessionId, seqStr := config.ExtractMetaFromRequest(request, path)

	if request.Method == config.GetNormalizedUplinkHTTPMethod() && sessionId != "" && seqStr != "" {
		// packet-up
		seq, err := strconv.ParseInt(seqStr, 10, 64)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		// decode body
		placement := config.GetNormalizedUplinkDataPlacement()
		var payload []byte
		if placement == PlacementHeader {
			encoded := request.Header.Get(config.GetNormalizedUplinkDataKey() + "-0")
			payload, _ = base64.RawURLEncoding.DecodeString(encoded)
		} else {
			payload = body
		}

		session := h.upsertSession(sessionId)
		if err := session.uploadQueue.Push(Packet{Payload: payload, Seq: uint64(seq)}); err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		writer.WriteHeader(http.StatusOK)
		return
	}

	if request.Method == "GET" || request.Method == config.GetNormalizedUplinkHTTPMethod() {
		// stream-down or stream-one or stream-up
		mode := "stream-up"
		if request.Method == "GET" {
			mode = "stream-down"
		}
		if sessionId == "" && request.Method == config.GetNormalizedUplinkHTTPMethod() {
			mode = "stream-one"
		}

		var currentSession *httpSession
		if mode != "stream-one" {
			if sessionId == "" {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			currentSession = h.upsertSession(sessionId)
			currentSession.fullyConnected()
			defer h.sessions.Delete(sessionId)
		}

		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}

		httpSC := &httpServerConn{
			waitCh:         make(chan struct{}),
			Reader:         request.Body,
			ResponseWriter: writer,
		}
		conn := &splitConn{
			writer:     httpSC,
			reader:     httpSC,
			remoteAddr: request.RemoteAddr,
			localAddr:  request.Host,
		}
		if currentSession != nil { // if not stream-one
			conn.reader = currentSession.uploadQueue
		}

		h.addConn(conn)

		select {
		case <-request.Context().Done():
		case <-httpSC.waitCh:
		}
		conn.Close()
	} else {
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type httpServerConn struct {
	sync.Mutex
	waitCh   chan struct{}
	waitOnce sync.Once
	io.Reader
	http.ResponseWriter
}

func (c *httpServerConn) Close() error {
	c.waitOnce.Do(func() { close(c.waitCh) })
	return nil
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()

	n, err := c.ResponseWriter.Write(b)
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
	if err != nil {
		c.Close()
	}
	return n, err
}

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr string
	localAddr  string
}

func (c *splitConn) Write(b []byte) (int, error) { return c.writer.Write(b) }
func (c *splitConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *splitConn) Close() error {
	err1 := c.writer.Close()
	err2 := c.reader.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

func (c *splitConn) LocalAddr() net.Addr                { return dummyAddr(c.localAddr) }
func (c *splitConn) RemoteAddr() net.Addr               { return dummyAddr(c.remoteAddr) }
func (c *splitConn) SetDeadline(t time.Time) error      { return nil }
func (c *splitConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *splitConn) SetWriteDeadline(t time.Time) error { return nil }
