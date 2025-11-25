package xhttp

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/quic-go"
	http3 "github.com/metacubex/quic-go/http3"
	tls "github.com/metacubex/utls"
	"golang.org/x/net/http2"
)

type requestHandler struct {
	config    *Config
	sessions  sync.Map
	tunnel    C.Tunnel
	additions []inbound.Addition
}

func (h *requestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.validateRequest(r); err != nil {
		log.Debugln("xhttp: validation failed: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sessionID, err := h.parseSessionID(r.URL.Path)
	if err != nil {
		log.Debugln("xhttp: invalid session ID: %v", err)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		h.handleDownload(w, r, sessionID)
		return
	}

	if r.Method == http.MethodPost {
		if seq, err := h.parseSeq(r.URL.Path); err == nil {
			h.handlePacketUpload(w, r, sessionID, seq)
		} else {
			h.handleStreamUpload(w, r, sessionID)
		}
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func (h *requestHandler) validateRequest(r *http.Request) error {
	if h.config.Host != "" && r.Host != h.config.Host && r.Host != "" {
		return fmt.Errorf("host mismatch: expected %s, got %s", h.config.Host, r.Host)
	}

	if !strings.HasPrefix(r.URL.Path, h.config.Path) {
		return fmt.Errorf("path mismatch: expected prefix %s", h.config.Path)
	}

	return nil
}

func isValidSessionID(id string) bool {
	_, err := uuid.FromString(id)
	return err == nil
}

func (h *requestHandler) parseSessionID(path string) (string, error) {
	if !strings.HasPrefix(path, h.config.Path) {
		return "", errors.New("invalid path prefix")
	}

	remainder := strings.TrimPrefix(path, h.config.Path)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")

	if len(parts) < 1 || parts[0] == "" {
		return "", errors.New("missing session ID")
	}

	sessionID := parts[0]
	if !isValidSessionID(sessionID) {
		return "", errors.New("invalid session ID format")
	}

	return sessionID, nil
}

func (h *requestHandler) parseSeq(path string) (uint64, error) {
	remainder := strings.TrimPrefix(path, h.config.Path)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")

	if len(parts) < 2 {
		return 0, errors.New("missing sequence number")
	}

	seq, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid sequence number: %w", err)
	}

	return seq, nil
}

func (h *requestHandler) getOrCreateSession(sessionId string) (*httpSession, error) {
	if val, ok := h.sessions.Load(sessionId); ok {
		return val.(*httpSession), nil
	}

	maxPackets := DefaultMaxPackets
	if !h.config.ScMaxBufferedPosts.IsZero() {
		maxPackets = int(h.config.ScMaxBufferedPosts.Random())
	}

	session := newHTTPSession(sessionId, maxPackets)
	actual, _ := h.sessions.LoadOrStore(sessionId, session)
	return actual.(*httpSession), nil
}

func (h *requestHandler) applyResponseHeaders(w http.ResponseWriter) {
	if !h.config.NoGRPCHeader {
		w.Header().Set("Content-Type", "application/grpc")
	} else if !h.config.NoSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	for k, v := range h.config.Headers {
		w.Header().Set(k, v)
	}
}

func (h *requestHandler) handleDownload(w http.ResponseWriter, r *http.Request, sessionID string) {
	session, err := h.getOrCreateSession(sessionID)
	if err != nil {
		log.Warnln("xhttp: failed to get session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.applyResponseHeaders(w)
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	var keepAliveTicker *time.Ticker
	var keepAliveInterval time.Duration
	if !h.config.ScStreamUpServerSecs.IsZero() {
		secs := h.config.ScStreamUpServerSecs.Random()
		if secs > 0 {
			keepAliveInterval = time.Duration(secs) * time.Second
			keepAliveTicker = time.NewTicker(keepAliveInterval)
			defer keepAliveTicker.Stop()
		}
	}

	pollTicker := time.NewTicker(DefaultPollInterval)
	defer pollTicker.Stop()

	keepAliveByte := []byte{0x00}
	lastActivity := time.Now()

	for {
		select {
		case data, ok := <-session.downloadQueue:
			if !ok {
				session.close()
				h.sessions.Delete(sessionID)
				return
			}
			lastActivity = time.Now()
			if _, writeErr := w.Write(data); writeErr != nil {
				log.Debugln("xhttp: download write error: %v", writeErr)
				session.close()
				h.sessions.Delete(sessionID)
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}

		case <-r.Context().Done():
			log.Debugln("xhttp: client disconnected, closing session %s", sessionID)
			session.close()
			h.sessions.Delete(sessionID)
			return

		case <-pollTicker.C:
			if keepAliveTicker != nil && time.Since(lastActivity) >= keepAliveInterval {
				if _, writeErr := w.Write(keepAliveByte); writeErr != nil {
					log.Debugln("xhttp: keep-alive write error: %v", writeErr)
					session.close()
					h.sessions.Delete(sessionID)
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				lastActivity = time.Now()
			}
		}
	}
}

func (h *requestHandler) handleStreamUpload(w http.ResponseWriter, r *http.Request, sessionID string) {
	session, err := h.getOrCreateSession(sessionID)
	if err != nil {
		log.Warnln("xhttp: failed to get session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	packet := Packet{
		Reader: r.Body,
		Seq:    0,
	}

	if err := session.uploadQueue.Push(packet); err != nil {
		log.Warnln("xhttp: failed to push stream packet: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	localAddr, _ := net.ResolveTCPAddr("tcp", r.Host)
	if remoteAddr == nil {
		remoteAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}
	if localAddr == nil {
		localAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}

	if h.tunnel != nil {
		session.startTunnel(remoteAddr, localAddr, func(conn net.Conn) {
			h.tunnel.HandleTCPConn(inbound.NewSocket(socks5.ParseAddr("0.0.0.0:0"), conn, C.HTTPS, h.additions...))
		})
	}

	w.WriteHeader(http.StatusOK)
}

func (h *requestHandler) handlePacketUpload(w http.ResponseWriter, r *http.Request, sessionID string, seq uint64) {
	session, err := h.getOrCreateSession(sessionID)
	if err != nil {
		log.Warnln("xhttp: failed to get session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	maxBytes := int(h.config.ScMaxEachPostBytes.Random())
	if maxBytes <= 0 {
		maxBytes = 1024 * 1024
	}

	payload := make([]byte, maxBytes)
	n, err := io.ReadFull(r.Body, payload)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		log.Warnln("xhttp: failed to read packet: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	packet := Packet{
		Payload: payload[:n],
		Seq:     seq,
	}

	if err := session.uploadQueue.Push(packet); err != nil {
		log.Warnln("xhttp: failed to push packet: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	localAddr, _ := net.ResolveTCPAddr("tcp", r.Host)
	if remoteAddr == nil {
		remoteAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}
	if localAddr == nil {
		localAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}

	if h.tunnel != nil {
		session.startTunnel(remoteAddr, localAddr, func(conn net.Conn) {
			h.tunnel.HandleTCPConn(inbound.NewSocket(socks5.ParseAddr("0.0.0.0:0"), conn, C.HTTPS, h.additions...))
		})
	}

	w.WriteHeader(http.StatusOK)
}

func NewHTTP1Server(config *Config, tunnel C.Tunnel, additions []inbound.Addition) (*http.Server, error) {
	if config == nil {
		return nil, errors.New("xhttp: config is required")
	}
	handler := &requestHandler{
		config:    config,
		tunnel:    tunnel,
		additions: additions,
	}
	return &http.Server{
		Handler: handler,
	}, nil
}

func NewHTTP2Server(config *Config, tunnel C.Tunnel, additions []inbound.Addition, tlsCfg *stdtls.Config) (*http.Server, error) {
	if config == nil {
		return nil, errors.New("xhttp: config is required")
	}
	if tlsCfg == nil {
		tlsCfg = &stdtls.Config{}
	}
	if len(tlsCfg.NextProtos) == 0 {
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	}
	handler := &requestHandler{
		config:    config,
		tunnel:    tunnel,
		additions: additions,
	}
	srv := &http.Server{
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
	if err := http2.ConfigureServer(srv, nil); err != nil {
		return nil, fmt.Errorf("xhttp: failed to configure HTTP/2: %w", err)
	}
	return srv, nil
}

func NewHTTP3Server(config *Config, tunnel C.Tunnel, additions []inbound.Addition, tlsCfg *tls.Config) (*http3.Server, error) {
	if config == nil {
		return nil, errors.New("xhttp: config is required")
	}
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}
	if tlsCfg.MinVersion < tls.VersionTLS13 {
		tlsCfg.MinVersion = tls.VersionTLS13
	}
	if len(tlsCfg.NextProtos) == 0 {
		tlsCfg.NextProtos = []string{"h3"}
	}
	handler := &requestHandler{
		config:    config,
		tunnel:    tunnel,
		additions: additions,
	}
	quicCfg := &quic.Config{
		MaxIdleTimeout: 60 * 1000000000,
	}
	return &http3.Server{
		Handler:         handler,
		TLSConfig:       tlsCfg,
		QUICConfig:      quicCfg,
		Addr:            "",
		EnableDatagrams: false,
	}, nil
}

func NewServer(ctx context.Context, config *Config, tunnel C.Tunnel, additions []inbound.Addition, listener net.Listener, tlsCfg interface{}) error {
	if config == nil {
		return errors.New("xhttp: config is required")
	}
	if listener == nil {
		return errors.New("xhttp: listener is required")
	}

	config.normalize()
	httpVersion := config.httpVersion(tlsCfg != nil)

	switch httpVersion {
	case "3":
		utlsCfg, ok := tlsCfg.(*tls.Config)
		if !ok && tlsCfg != nil {
			return errors.New("xhttp: HTTP/3 requires *tls.Config")
		}
		srv, err := NewHTTP3Server(config, tunnel, additions, utlsCfg)
		if err != nil {
			return err
		}
		packetConn, ok := listener.(net.PacketConn)
		if !ok {
			return errors.New("xhttp: HTTP/3 requires PacketConn listener")
		}
		go func() {
			if err := srv.Serve(packetConn); err != nil && err != http.ErrServerClosed {
				log.Errorln("xhttp: HTTP/3 server error: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
		return nil

	case "2":
		stdTLSCfg, ok := tlsCfg.(*stdtls.Config)
		if !ok && tlsCfg != nil {
			return errors.New("xhttp: HTTP/2 requires *tls.Config")
		}
		srv, err := NewHTTP2Server(config, tunnel, additions, stdTLSCfg)
		if err != nil {
			return err
		}
		go func() {
			if err := srv.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
				log.Errorln("xhttp: HTTP/2 server error: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
		return nil

	default:
		srv, err := NewHTTP1Server(config, tunnel, additions)
		if err != nil {
			return err
		}
		go func() {
			if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
				log.Errorln("xhttp: HTTP/1.1 server error: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
		return nil
	}
}
