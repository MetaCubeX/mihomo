package tuic

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic/common"
	v4 "github.com/metacubex/mihomo/transport/tuic/v4"
	v5 "github.com/metacubex/mihomo/transport/tuic/v5"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
)

type ServerOption struct {
	HandleTcpFn func(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error
	HandleUdpFn func(addr socks5.Addr, packet C.UDPPacket, additions ...inbound.Addition) error

	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Tokens                [][32]byte          // V4 special
	Users                 map[[16]byte]string // V5 special
	CongestionController  string
	AuthenticationTimeout time.Duration
	MaxUdpRelayPacketSize int
	CWND                  int
}

type Server struct {
	*ServerOption
	optionV4 *v4.ServerOption
	optionV5 *v5.ServerOption
	listener *quic.EarlyListener
}

func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		common.SetCongestionController(conn, s.CongestionController, s.CWND)
		h := &serverHandler{
			Server:   s,
			quicConn: conn,
			uuid:     utils.NewUUIDV4(),
		}
		if h.optionV4 != nil {
			h.v4Handler = v4.NewServerHandler(h.optionV4, conn, h.uuid)
		}
		if h.optionV5 != nil {
			h.v5Handler = v5.NewServerHandler(h.optionV5, conn, h.uuid)
		}
		go h.handle()
	}
}

func (s *Server) Close() error {
	return s.listener.Close()
}

type serverHandler struct {
	*Server
	quicConn quic.EarlyConnection
	uuid     uuid.UUID

	v4Handler common.ServerHandler
	v5Handler common.ServerHandler
}

func (s *serverHandler) handle() {
	go func() {
		_ = s.handleUniStream()
	}()
	go func() {
		_ = s.handleStream()
	}()
	go func() {
		_ = s.handleMessage()
	}()

	<-s.quicConn.HandshakeComplete()
	time.AfterFunc(s.AuthenticationTimeout, func() {
		if s.v4Handler != nil {
			if s.v4Handler.AuthOk() {
				return
			}
		}

		if s.v5Handler != nil {
			if s.v5Handler.AuthOk() {
				return
			}
		}

		if s.v4Handler != nil {
			s.v4Handler.HandleTimeout()
		}

		if s.v5Handler != nil {
			s.v5Handler.HandleTimeout()
		}
	})
}

func (s *serverHandler) handleMessage() (err error) {
	for {
		var message []byte
		message, err = s.quicConn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		go func() (err error) {
			if len(message) > 0 {
				switch message[0] {
				case v4.VER:
					if s.v4Handler != nil {
						return s.v4Handler.HandleMessage(message)
					}
				case v5.VER:
					if s.v5Handler != nil {
						return s.v5Handler.HandleMessage(message)
					}
				}
			}
			return
		}()
	}
}

func (s *serverHandler) handleStream() (err error) {
	for {
		var quicStream quic.Stream
		quicStream, err = s.quicConn.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		go func() (err error) {
			stream := common.NewQuicStreamConn(
				quicStream,
				s.quicConn.LocalAddr(),
				s.quicConn.RemoteAddr(),
				nil,
			)
			conn := N.NewBufferedConn(stream)

			verBytes, err := conn.Peek(1)
			if err != nil {
				_ = conn.Close()
				return err
			}

			switch verBytes[0] {
			case v4.VER:
				if s.v4Handler != nil {
					return s.v4Handler.HandleStream(conn)
				}
			case v5.VER:
				if s.v5Handler != nil {
					return s.v5Handler.HandleStream(conn)
				}
			}
			return
		}()
	}
}

func (s *serverHandler) handleUniStream() (err error) {
	for {
		var stream quic.ReceiveStream
		stream, err = s.quicConn.AcceptUniStream(context.Background())
		if err != nil {
			return err
		}
		go func() (err error) {
			defer func() {
				stream.CancelRead(0)
			}()
			reader := bufio.NewReader(stream)
			verBytes, err := reader.Peek(1)
			if err != nil {
				return err
			}

			switch verBytes[0] {
			case v4.VER:
				if s.v4Handler != nil {
					return s.v4Handler.HandleUniStream(reader)
				}
			case v5.VER:
				if s.v5Handler != nil {
					return s.v5Handler.HandleUniStream(reader)
				}
			}
			return
		}()
	}
}

func NewServer(option *ServerOption, pc net.PacketConn) (*Server, error) {
	listener, err := quic.ListenEarly(pc, option.TlsConfig, option.QuicConfig)
	if err != nil {
		return nil, err
	}
	server := &Server{
		ServerOption: option,
		listener:     listener,
	}
	if len(option.Tokens) > 0 {
		server.optionV4 = &v4.ServerOption{
			HandleTcpFn:           option.HandleTcpFn,
			HandleUdpFn:           option.HandleUdpFn,
			Tokens:                option.Tokens,
			MaxUdpRelayPacketSize: option.MaxUdpRelayPacketSize,
		}
	}
	if len(option.Users) > 0 {
		maxUdpRelayPacketSize := option.MaxUdpRelayPacketSize
		if maxUdpRelayPacketSize > MaxFragSizeV5 {
			maxUdpRelayPacketSize = MaxFragSizeV5
		}
		server.optionV5 = &v5.ServerOption{
			HandleTcpFn:           option.HandleTcpFn,
			HandleUdpFn:           option.HandleUdpFn,
			Users:                 option.Users,
			MaxUdpRelayPacketSize: option.MaxUdpRelayPacketSize,
		}
	}
	return server, nil
}
