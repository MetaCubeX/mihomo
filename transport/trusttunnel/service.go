package trusttunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
	N "github.com/metacubex/mihomo/common/net"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httputil"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
	"github.com/metacubex/tls"
)

type Handler interface {
	network.TCPConnectionHandler
	network.UDPConnectionHandler
}

type ICMPHandler interface {
	NewICMPConnection(ctx context.Context, conn *IcmpConn)
}

type ServiceOptions struct {
	Ctx                   context.Context
	Logger                logger.ContextLogger
	Handler               Handler
	ICMPHandler           ICMPHandler
	QUICCongestionControl string
	QUICCwnd              int
	QUICBBRProfile        string
	// Fallback is an optional backend (host:port) that unauthenticated requests are
	// served from, so a probe gets the backend's responses instead of a proxy's 407.
	Fallback string
}

type Service struct {
	ctx                   context.Context
	logger                logger.ContextLogger
	users                 map[string]string
	handler               Handler
	icmpHandler           ICMPHandler
	quicCongestionControl string
	quicCwnd              int
	quicBBRProfile        string
	httpServer            *http.Server
	h3Server              *http3.Server
	tcpListener           net.Listener
	tlsListener           net.Listener
	udpConn               net.PacketConn
	fallbackProxy         *httputil.ReverseProxy
	fallbackTransport     *http.Transport
}

func NewService(options ServiceOptions) *Service {
	s := &Service{
		ctx:                   options.Ctx,
		logger:                options.Logger,
		handler:               options.Handler,
		icmpHandler:           options.ICMPHandler,
		quicCongestionControl: options.QUICCongestionControl,
		quicCwnd:              options.QUICCwnd,
		quicBBRProfile:        options.QUICBBRProfile,
	}
	if options.Fallback != "" {
		s.fallbackTransport = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       30 * time.Second,
		}
		target := options.Fallback
		s.fallbackProxy = &httputil.ReverseProxy{
			Transport:     s.fallbackTransport,
			FlushInterval: -1, // flush each write so SSE and streaming are not buffered
			// Rewrite (unlike Director) drops any Forwarded/X-Forwarded-* the client
			// sent, so a prober cannot spoof the IP, scheme or host the backend sees.
			Rewrite: func(r *httputil.ProxyRequest) {
				r.Out.URL.Scheme = "http"
				r.Out.URL.Host = target
				// Keep the client's Host header: named virtual hosts keep working and
				// the internal backend address is not leaked in redirects.
				r.Out.Host = r.In.Host
				r.SetXForwarded()
			},
			ErrorHandler: func(writer http.ResponseWriter, request *http.Request, err error) {
				if s.logger != nil {
					s.logger.DebugContext(request.Context(), E.Cause(err, "fallback request from ", request.RemoteAddr))
				}
				writer.WriteHeader(http.StatusBadGateway)
			},
		}
	}
	return s
}

func (s *Service) Start(tcpListener net.Listener, udpConn net.PacketConn, tlsConfig *tls.Config) error {
	if tcpListener != nil {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetHTTP2(true)
		// Enable HTTP/2 support unconditionally on the server.
		//
		// Note that this usage is limited to our own net/http fork
		// The standard library also needs to mask the tls.Conn type for the conn returned by the Listener.
		// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
		protocols.SetUnencryptedHTTP2(true)
		s.httpServer = &http.Server{
			Handler:     s,
			IdleTimeout: DefaultSessionTimeout,
			BaseContext: func(net.Listener) context.Context {
				return s.ctx
			},
			Protocols: protocols,
		}
		listener := tcpListener
		s.tcpListener = tcpListener
		if tlsConfig != nil {
			tcpTLSConfig := tlsConfig
			if s.fallbackProxy != nil && len(tlsConfig.NextProtos) == 0 {
				// A real HTTPS site negotiates ALPN, so a browser or scanner offering
				// h2 gets h2 instead of no protocol at all. TrustTunnel clients offer
				// h2 and keep working.
				tcpTLSConfig = tlsConfig.Clone()
				tcpTLSConfig.NextProtos = []string{"h2", "http/1.1"}
			}
			listener = tls.NewListener(listener, tcpTLSConfig)
			s.tlsListener = listener
		}
		go func() {
			sErr := s.httpServer.Serve(listener)
			if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				s.logger.ErrorContext(s.ctx, "HTTP server close: ", sErr)
			}
		}()
	}
	if udpConn != nil {
		err := s.configHTTP3Server(tlsConfig, udpConn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) UpdateUsers(users map[string]string) {
	s.users = users
}

func (s *Service) Close() error {
	var shutdownErr error
	if s.httpServer != nil {
		const shutdownTimeout = 5 * time.Second
		ctx, cancel := context.WithTimeout(s.ctx, shutdownTimeout)
		shutdownErr = s.httpServer.Shutdown(ctx)
		cancel()
		if errors.Is(shutdownErr, http.ErrServerClosed) {
			shutdownErr = nil
		}
	}
	if s.fallbackTransport != nil {
		s.fallbackTransport.CloseIdleConnections()
	}
	closeErr := common.Close(
		common.PtrOrNil(s.httpServer),
		s.tlsListener,
		s.tcpListener,
		common.PtrOrNil(s.h3Server),
		s.udpConn,
	)
	return E.Errors(shutdownErr, closeErr)
}

func (s *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	authorization := request.Header.Get("Proxy-Authorization")
	username, loaded := s.verify(authorization)
	if !loaded {
		if s.fallbackProxy != nil {
			// Every method goes to the backend, CONNECT included, so a probe gets
			// the backend's own answer rather than a proxy's 407 challenge.
			s.fallbackProxy.ServeHTTP(writer, request)
			return
		}
		writer.WriteHeader(http.StatusProxyAuthRequired)
		s.badRequest(request.Context(), request, E.New("authorization failed"))
		return
	}
	if request.Method != http.MethodConnect {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		s.badRequest(request.Context(), request, E.New("unexpected HTTP method ", request.Method))
		return
	}
	ctx := request.Context()
	ctx = auth.ContextWithUser(ctx, username)
	s.logger.DebugContext(ctx, "[", username, "] ", "request from ", request.RemoteAddr)
	s.logger.DebugContext(ctx, "[", username, "] ", "request to ", request.Host)
	switch request.Host {
	case UDPMagicAddress:
		writer.WriteHeader(http.StatusOK)
		flusher, isFlusher := writer.(http.Flusher)
		if isFlusher {
			flusher.Flush()
		}
		conn := &serverPacketConn{
			packetConn: packetConn{
				httpConn: httpConn{
					writer:  writer,
					flusher: flusher,
					created: make(chan struct{}),
				},
			},
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, request)
		conn.setup(request.Body, nil)
		firstPacket := buf.NewPacket()
		destination, err := conn.ReadPacket(firstPacket)
		if err != nil {
			firstPacket.Release()
			_ = conn.Close()
			s.logger.ErrorContext(ctx, E.Cause(err, "read first packet of ", request.RemoteAddr))
			return
		}
		destination = destination.Unwrap()
		cachedConn := bufio.NewCachedPacketConn(conn, firstPacket, destination)
		_ = s.handler.NewPacketConnection(ctx, cachedConn, M.Metadata{
			Protocol:    "trusttunnel",
			Source:      M.ParseSocksaddr(request.RemoteAddr),
			Destination: destination,
		})
	case ICMPMagicAddress:
		flusher, isFlusher := writer.(http.Flusher)
		if s.icmpHandler == nil {
			writer.WriteHeader(http.StatusNotImplemented)
			if isFlusher {
				flusher.Flush()
			}
			_ = request.Body.Close()
		} else {
			writer.WriteHeader(http.StatusOK)
			if isFlusher {
				flusher.Flush()
			}
			conn := &IcmpConn{
				httpConn{
					writer:  writer,
					flusher: flusher,
					created: make(chan struct{}),
				},
			}
			httputils.SetAddrFromRequest(&conn.NetAddr, request)
			conn.setup(request.Body, nil)
			s.icmpHandler.NewICMPConnection(ctx, conn)
		}
	case HealthCheckMagicAddress:
		writer.WriteHeader(http.StatusOK)
		if flusher, isFlusher := writer.(http.Flusher); isFlusher {
			flusher.Flush()
		}
		_ = request.Body.Close()
	default:
		writer.WriteHeader(http.StatusOK)
		flusher, isFlusher := writer.(http.Flusher)
		if isFlusher {
			flusher.Flush()
		}
		conn := &tcpConn{
			httpConn{
				writer:  writer,
				flusher: flusher,
				created: make(chan struct{}),
			},
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, request)
		conn.setup(request.Body, nil)
		wrapper := &h2ConnWrapper{
			ExtendedConn: N.NewDeadlineConn(conn),
		}
		_ = s.handler.NewConnection(ctx, wrapper, M.Metadata{
			Protocol:    "trusttunnel",
			Source:      M.ParseSocksaddr(request.RemoteAddr),
			Destination: M.ParseSocksaddr(request.Host).Unwrap(),
		})
		wrapper.CloseWrapper()
	}
}

func (s *Service) verify(authorization string) (username string, loaded bool) {
	username, password, loaded := parseBasicAuth(authorization)
	if !loaded {
		return "", false
	}
	recordedPassword, loaded := s.users[username]
	if !loaded {
		return "", false
	}
	if password != recordedPassword {
		return "", false
	}
	return username, true
}

func (s *Service) badRequest(ctx context.Context, request *http.Request, err error) {
	s.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
}

// h2ConnWrapper used to avoid "panic: Write called after Handler finished" for gun.Conn
type h2ConnWrapper struct {
	N.ExtendedConn
	access sync.Mutex
	closed bool
}

func (w *h2ConnWrapper) Write(p []byte) (n int, err error) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.closed {
		return 0, net.ErrClosed
	}
	return w.ExtendedConn.Write(p)
}

func (w *h2ConnWrapper) WriteBuffer(buffer *buf.Buffer) error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	return w.ExtendedConn.WriteBuffer(buffer)
}

func (w *h2ConnWrapper) CloseWrapper() {
	w.access.Lock()
	defer w.access.Unlock()
	w.closed = true
}

func (w *h2ConnWrapper) Upstream() any {
	return w.ExtendedConn
}
