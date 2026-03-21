package trusttunnel

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/h2c"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/tls"
)

type Handler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
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
}

type Service struct {
	ctx                   context.Context
	logger                logger.ContextLogger
	users                 map[string]string
	handler               Handler
	icmpHandler           ICMPHandler
	quicCongestionControl string
	quicCwnd              int
	httpServer            *http.Server
	h2Server              *http.Http2Server
	h3Server              *http3.Server
	tcpListener           net.Listener
	tlsListener           net.Listener
	udpConn               net.PacketConn
}

func NewService(options ServiceOptions) *Service {
	return &Service{
		ctx:                   options.Ctx,
		logger:                options.Logger,
		handler:               options.Handler,
		icmpHandler:           options.ICMPHandler,
		quicCongestionControl: options.QUICCongestionControl,
		quicCwnd:              options.QUICCwnd,
	}
}

func (s *Service) Start(tcpListener net.Listener, udpConn net.PacketConn, tlsConfig *tls.Config) error {
	if tcpListener != nil {
		h2Server := &http.Http2Server{}
		s.httpServer = &http.Server{
			Handler:     h2c.NewHandler(s, h2Server),
			IdleTimeout: DefaultSessionTimeout,
			BaseContext: func(net.Listener) context.Context {
				return s.ctx
			},
		}
		err := http.Http2ConfigureServer(s.httpServer, h2Server)
		if err != nil {
			return err
		}
		s.h2Server = h2Server
		listener := tcpListener
		s.tcpListener = tcpListener
		if tlsConfig != nil {
			listener = tls.NewListener(listener, tlsConfig)
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
		conn.SetAddrFromRequest(request)
		conn.setUp(request.Body, nil)
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
			conn.SetAddrFromRequest(request)
			conn.setUp(request.Body, nil)
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
		conn.SetAddrFromRequest(request)
		conn.setUp(request.Body, nil)
		_ = s.handler.NewConnection(ctx, conn, M.Metadata{
			Protocol:    "trusttunnel",
			Source:      M.ParseSocksaddr(request.RemoteAddr),
			Destination: M.ParseSocksaddr(request.Host).Unwrap(),
		})
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
