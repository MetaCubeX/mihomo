package v5

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"

	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/utils"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
	"github.com/Dreamacro/clash/transport/tuic/common"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
)

type ServerOption struct {
	HandleTcpFn func(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error
	HandleUdpFn func(addr socks5.Addr, packet C.UDPPacket, additions ...inbound.Addition) error

	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Users                 map[[16]byte]string
	CongestionController  string
	AuthenticationTimeout time.Duration
	MaxUdpRelayPacketSize int
	CWND                  int
}

type Server struct {
	*ServerOption
	listener *quic.EarlyListener
}

func NewServer(option *ServerOption, pc net.PacketConn) (*Server, error) {
	listener, err := quic.ListenEarly(pc, option.TlsConfig, option.QuicConfig)
	if err != nil {
		return nil, err
	}
	return &Server{
		ServerOption: option,
		listener:     listener,
	}, err
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
			authCh:   make(chan struct{}),
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

	authCh   chan struct{}
	authOk   bool
	authUUID string
	authOnce sync.Once

	udpInputMap sync.Map
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
		s.authOnce.Do(func() {
			_ = s.quicConn.CloseWithError(AuthenticationTimeout, "AuthenticationTimeout")
			s.authOk = false
			close(s.authCh)
		})
	})
}

func (s *serverHandler) handleMessage() (err error) {
	for {
		var message []byte
		message, err = s.quicConn.ReceiveMessage()
		if err != nil {
			return err
		}
		go func() (err error) {
			reader := bytes.NewBuffer(message)
			commandHead, err := ReadCommandHead(reader)
			if err != nil {
				return
			}
			switch commandHead.TYPE {
			case PacketType:
				var packet Packet
				packet, err = ReadPacketWithHead(commandHead, reader)
				if err != nil {
					return
				}
				return s.parsePacket(packet, common.NATIVE)
			case HeartbeatType:
				var heartbeat Heartbeat
				heartbeat, err = ReadHeartbeatWithHead(commandHead, reader)
				if err != nil {
					return
				}
				heartbeat.BytesLen()
			}
			return
		}()
	}
}

func (s *serverHandler) parsePacket(packet Packet, udpRelayMode common.UdpRelayMode) (err error) {
	<-s.authCh
	if !s.authOk {
		return
	}
	var assocId uint16

	assocId = packet.ASSOC_ID

	v, _ := s.udpInputMap.LoadOrStore(assocId, &serverUDPInput{})
	input := v.(*serverUDPInput)
	if input.writeClosed.Load() {
		return nil
	}
	packetPtr := input.Feed(packet)
	if packetPtr == nil {
		return
	}

	pc := &quicStreamPacketConn{
		connId:                assocId,
		quicConn:              s.quicConn,
		inputConn:             nil,
		udpRelayMode:          udpRelayMode,
		maxUdpRelayPacketSize: s.MaxUdpRelayPacketSize,
		deferQuicConnFn:       nil,
		closeDeferFn:          nil,
		writeClosed:           &input.writeClosed,
	}

	return s.HandleUdpFn(packetPtr.ADDR.SocksAddr(), &serverUDPPacket{
		pc:     pc,
		packet: packetPtr,
		rAddr:  N.NewCustomAddr("tuic", fmt.Sprintf("tuic-%s-%d", s.uuid, assocId), s.quicConn.RemoteAddr()), // for tunnel's handleUDPConn
	}, inbound.WithInUser(s.authUUID))
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
			connect, err := ReadConnect(conn)
			if err != nil {
				return err
			}
			<-s.authCh
			if !s.authOk {
				return conn.Close()
			}

			err = s.HandleTcpFn(conn, connect.ADDR.SocksAddr(), inbound.WithInUser(s.authUUID))
			if err != nil {
				_ = conn.Close()
				return err
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
			commandHead, err := ReadCommandHead(reader)
			if err != nil {
				return
			}
			switch commandHead.TYPE {
			case AuthenticateType:
				var authenticate Authenticate
				authenticate, err = ReadAuthenticateWithHead(commandHead, reader)
				if err != nil {
					return
				}
				authOk := false
				var authUUID uuid.UUID
				var token [32]byte
				if password, ok := s.Users[authenticate.UUID]; ok {
					token, err = GenToken(s.quicConn.ConnectionState(), authenticate.UUID, password)
					if err != nil {
						return
					}
					if token == authenticate.TOKEN {
						authOk = true
						authUUID = authenticate.UUID
					}
				}
				s.authOnce.Do(func() {
					if !authOk {
						_ = s.quicConn.CloseWithError(AuthenticationFailed, "AuthenticationFailed")
					}
					s.authOk = authOk
					s.authUUID = authUUID.String()
					close(s.authCh)
				})
			case PacketType:
				var packet Packet
				packet, err = ReadPacketWithHead(commandHead, reader)
				if err != nil {
					return
				}
				return s.parsePacket(packet, common.QUIC)
			case DissociateType:
				var disassociate Dissociate
				disassociate, err = ReadDissociateWithHead(commandHead, reader)
				if err != nil {
					return
				}
				if v, loaded := s.udpInputMap.LoadAndDelete(disassociate.ASSOC_ID); loaded {
					input := v.(*serverUDPInput)
					input.writeClosed.Store(true)
				}
			}
			return
		}()
	}
}

type serverUDPInput struct {
	writeClosed atomic.Bool
	deFragger
}

type serverUDPPacket struct {
	pc     *quicStreamPacketConn
	packet *Packet
	rAddr  net.Addr
}

func (s *serverUDPPacket) InAddr() net.Addr {
	return s.pc.LocalAddr()
}

func (s *serverUDPPacket) LocalAddr() net.Addr {
	return s.rAddr
}

func (s *serverUDPPacket) Data() []byte {
	return s.packet.DATA
}

func (s *serverUDPPacket) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	return s.pc.WriteTo(b, addr)
}

func (s *serverUDPPacket) Drop() {
	s.packet.DATA = nil
}

var _ C.UDPPacket = (*serverUDPPacket)(nil)
var _ C.UDPPacketInAddr = (*serverUDPPacket)(nil)
