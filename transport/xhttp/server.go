package xhttp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
	N "github.com/metacubex/mihomo/common/net"

	"github.com/metacubex/http"
)

type ServerOption struct {
	Config
	ConnHandler func(net.Conn, *http.Request)
	HttpHandler http.Handler
}

type httpServerConn struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher
	reader  io.ReadCloser
	closed  bool
	done    chan struct{}
	once    sync.Once
}

func newHTTPServerConn(w http.ResponseWriter, r io.ReadCloser) *httpServerConn {
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
	return c.reader.Close()
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
	connHandler func(net.Conn, *http.Request)
	httpHandler http.Handler

	xPaddingBytes        Range
	scMaxEachPostBytes   Range
	scStreamUpServerSecs Range
	scMaxBufferedPosts   Range

	mu       sync.Mutex
	sessions map[string]*httpSession
}

func NewServerHandler(opt ServerOption) (http.Handler, error) {
	xPaddingBytes, err := opt.Config.GetNormalizedXPaddingBytes()
	if err != nil {
		return nil, err
	}
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
	return &requestHandler{
		config:               opt.Config,
		connHandler:          opt.ConnHandler,
		httpHandler:          opt.HttpHandler,
		xPaddingBytes:        xPaddingBytes,
		scMaxEachPostBytes:   scMaxEachPostBytes,
		scStreamUpServerSecs: scStreamUpServerSecs,
		scMaxBufferedPosts:   scMaxBufferedPosts,
		sessions:             map[string]*httpSession{},
	}, nil
}

func (h *requestHandler) upsertSession(sessionID string) *httpSession {
	h.mu.Lock()
	defer h.mu.Unlock()

	s, ok := h.sessions[sessionID]
	if ok {
		return s
	}

	s = newHTTPSession(h.scMaxBufferedPosts.Max)
	h.sessions[sessionID] = s

	// Reap orphan sessions that never become fully connected (e.g. from probing).
	// Matches Xray-core's 30-second reaper in upsertSession.
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			h.deleteSession(sessionID)
		case <-s.connected:
		}
	}()

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

	h.config.WriteResponseHeader(w, r.Method, r.Header)
	length := h.xPaddingBytes.Rand()
	config := XPaddingConfig{Length: length}

	if h.config.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: h.config.XPaddingPlacement,
			Key:       h.config.XPaddingKey,
			Header:    h.config.XPaddingHeader,
		}
		config.Method = PaddingMethod(h.config.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementHeader,
			Header:    "X-Padding",
		}
	}

	h.config.ApplyXPaddingToResponse(w, config)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	paddingValue, _ := h.config.ExtractXPaddingFromRequest(r, h.config.XPaddingObfsMode)
	if !h.config.IsPaddingValid(paddingValue, h.xPaddingBytes.Min, h.xPaddingBytes.Max, PaddingMethod(h.config.XPaddingMethod)) {
		http.Error(w, "invalid xpadding", http.StatusBadRequest)
		return
	}
	obfsPaddingAccepted := h.config.XPaddingObfsMode && paddingValue != ""
	sessionId, seqStr := h.config.ExtractMetaFromRequest(r, path)

	var currentSession *httpSession
	if sessionId != "" {
		currentSession = h.upsertSession(sessionId)
	}

	// stream-up upload: POST /path/{session}
	if r.Method != http.MethodGet && sessionId != "" && seqStr == "" && h.allowStreamUpUpload() {
		httpSC := newHTTPServerConn(w, r.Body)
		err := currentSession.uploadQueue.Push(Packet{
			Reader: httpSC,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
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

		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex() // http1 need to enable full duplex manually
		_ = rc.Flush()            // force flush the response header

		hasLegacyRefererCompatMarker := r.Header.Get("Referer") != ""
		if (hasLegacyRefererCompatMarker || obfsPaddingAccepted) && h.scStreamUpServerSecs.Max > 0 {
			go func() {
				for {
					_, err := httpSC.Write(bytes.Repeat([]byte{'X'}, int(h.xPaddingBytes.Rand())))
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
	if r.Method != http.MethodGet && sessionId != "" && seqStr != "" && h.allowPacketUpUpload() {
		scMaxEachPostBytes := h.scMaxEachPostBytes.Max
		dataPlacement := h.config.GetNormalizedUplinkDataPlacement()
		uplinkDataKey := h.config.UplinkDataKey
		var headerPayload []byte
		var err error
		if dataPlacement == PlacementAuto || dataPlacement == PlacementHeader {
			var headerPayloadChunks []string
			for i := 0; true; i++ {
				chunk := r.Header.Get(fmt.Sprintf("%s-%d", uplinkDataKey, i))
				if chunk == "" {
					break
				}
				headerPayloadChunks = append(headerPayloadChunks, chunk)
			}
			headerPayloadEncoded := strings.Join(headerPayloadChunks, "")
			headerPayload, err = base64.RawURLEncoding.DecodeString(headerPayloadEncoded)
			if err != nil {
				http.Error(w, "invalid base64 in header's payload", http.StatusBadRequest)
				return
			}
		}

		var cookiePayload []byte
		if dataPlacement == PlacementAuto || dataPlacement == PlacementCookie {
			var cookiePayloadChunks []string
			for i := 0; true; i++ {
				cookieName := fmt.Sprintf("%s_%d", uplinkDataKey, i)
				if c, _ := r.Cookie(cookieName); c != nil {
					cookiePayloadChunks = append(cookiePayloadChunks, c.Value)
				} else {
					break
				}
			}
			cookiePayloadEncoded := strings.Join(cookiePayloadChunks, "")
			cookiePayload, err = base64.RawURLEncoding.DecodeString(cookiePayloadEncoded)
			if err != nil {
				http.Error(w, "invalid base64 in cookies' payload", http.StatusBadRequest)
				return
			}
		}

		var bodyPayload []byte
		if dataPlacement == PlacementAuto || dataPlacement == PlacementBody {
			if r.ContentLength > int64(scMaxEachPostBytes) {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			bodyPayload, err = io.ReadAll(io.LimitReader(r.Body, int64(scMaxEachPostBytes)+1))
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
		}

		var payload []byte
		switch dataPlacement {
		case PlacementHeader:
			payload = headerPayload
		case PlacementCookie:
			payload = cookiePayload
		case PlacementBody:
			payload = bodyPayload
		case PlacementAuto:
			payload = headerPayload
			payload = append(payload, cookiePayload...)
			payload = append(payload, bodyPayload...)
		}

		if len(payload) > h.scMaxEachPostBytes.Max {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}

		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid xhttp seq", http.StatusBadRequest)
			return
		}

		err = currentSession.uploadQueue.Push(Packet{
			Seq:     seq,
			Payload: payload,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(payload) == 0 {
			// Methods without a body are usually cached by default.
			w.Header().Set("Cache-Control", "no-store")
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// stream-up/packet-up download: GET /path/{session}
	if r.Method == http.MethodGet && sessionId != "" && seqStr == "" && h.allowSessionDownload() {
		currentSession.markConnected()

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

		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex() // http1 need to enable full duplex manually
		_ = rc.Flush()            // force flush the response header

		httpSC := newHTTPServerConn(w, r.Body)
		conn := &Conn{
			writer: httpSC,
			reader: currentSession.uploadQueue,
			onClose: func() {
				h.deleteSession(sessionId)
			},
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, r)

		go h.connHandler(N.NewDeadlineConn(conn), r)

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = conn.Close()
		return
	}

	// stream-one: POST /path
	if r.Method != http.MethodGet && sessionId == "" && seqStr == "" && h.allowStreamOne() {
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)

		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex() // http1 need to enable full duplex manually
		_ = rc.Flush()            // force flush the response header

		httpSC := newHTTPServerConn(w, r.Body)
		conn := &Conn{
			writer: httpSC,
			reader: httpSC,
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, r)

		go h.connHandler(N.NewDeadlineConn(conn), r)

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = conn.Close()
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
