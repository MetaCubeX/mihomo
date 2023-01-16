package tuic

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

	"github.com/gofrs/uuid"
	"github.com/metacubex/quic-go"

	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

type ServerOption struct {
	HandleTcpFn func(conn net.Conn, addr socks5.Addr) error
	HandleUdpFn func(addr socks5.Addr, packet C.UDPPacket) error

	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Tokens                [][32]byte
	CongestionController  string
	AuthenticationTimeout time.Duration
	MaxUdpRelayPacketSize int
}

type Server struct {
	*ServerOption
	listener quic.EarlyListener
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
		uuid, err := uuid.NewV4()
		if err != nil {
			return err
		}
		h := &serverHandler{
			Server:   s,
			quicConn: conn,
			uuid:     uuid,
			authCh:   make(chan struct{}),
		}
		go h.handle()
	}
}

func (s *Server) Close() error {
	return s.listener.Close()
}

type serverHandler struct {
	serverOption ServerOption
	*Server
	quicConn quic.Connection
	uuid     uuid.UUID

	authCh   chan struct{}
	authOk   bool
	authOnce sync.Once

	udpInputMap sync.Map
}

func (s *serverHandler) handle() {
	time.AfterFunc(s.AuthenticationTimeout, func() {
		s.authOnce.Do(func() {
			_ = s.quicConn.CloseWithError(AuthenticationTimeout, "")
			s.authOk = false
			close(s.authCh)
		})
	})
	go func() {
		_ = s.handleUniStream()
	}()
	go func() {
		_ = s.handleStream()
	}()
	go func() {
		_ = s.handleMessage()
	}()
}

func (s *serverHandler) handleMessage() (err error) {
	for {
		var message []byte
		message, err = s.quicConn.ReceiveMessage()
		if err != nil {
			return err
		}
		go func() (err error) {
			buffer := bytes.NewBuffer(message)
			packet, err := ReadPacket(buffer)
			if err != nil {
				return
			}
			return s.parsePacket(packet, "native")
		}()
	}
}

func (s *serverHandler) parsePacket(packet Packet, udpRelayMode string) (err error) {
	<-s.authCh
	if !s.authOk {
		return
	}
	var assocId uint32

	assocId = packet.ASSOC_ID

	v, _ := s.udpInputMap.LoadOrStore(assocId, &atomic.Bool{})
	writeClosed := v.(*atomic.Bool)
	if writeClosed.Load() {
		return nil
	}

	pc := &quicStreamPacketConn{
		connId:                assocId,
		quicConn:              s.quicConn,
		lAddr:                 s.quicConn.LocalAddr(),
		inputConn:             nil,
		udpRelayMode:          udpRelayMode,
		maxUdpRelayPacketSize: s.MaxUdpRelayPacketSize,
		deferQuicConnFn:       nil,
		closeDeferFn:          nil,
		writeClosed:           writeClosed,
	}

	return s.HandleUdpFn(packet.ADDR.SocksAddr(), &serverUDPPacket{
		pc:     pc,
		packet: &packet,
		rAddr:  s.genServerAssocIdAddr(assocId),
	})
}

func (s *serverHandler) genServerAssocIdAddr(assocId uint32) net.Addr {
	return ServerAssocIdAddr(fmt.Sprintf("tuic-%s-%d", s.uuid.String(), assocId))
}

func (s *serverHandler) handleStream() (err error) {
	for {
		var quicStream quic.Stream
		quicStream, err = s.quicConn.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		SetCongestionController(s.quicConn, s.CongestionController)
		go func() (err error) {
			stream := &quicStreamConn{
				Stream: quicStream,
				lAddr:  s.quicConn.LocalAddr(),
				rAddr:  s.quicConn.RemoteAddr(),
			}
			conn := N.NewBufferedConn(stream)
			connect, err := ReadConnect(conn)
			if err != nil {
				return err
			}
			<-s.authCh
			if !s.authOk {
				return conn.Close()
			}

			buf := pool.GetBuffer()
			defer pool.PutBuffer(buf)
			err = s.HandleTcpFn(conn, connect.ADDR.SocksAddr())
			if err != nil {
				err = NewResponseFailed().WriteTo(buf)
				defer conn.Close()
			} else {
				err = NewResponseSucceed().WriteTo(buf)
			}
			if err != nil {
				_ = conn.Close()
				return err
			}
			_, err = buf.WriteTo(stream)
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
		SetCongestionController(s.quicConn, s.CongestionController)
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
				ok := false
				for _, tkn := range s.Tokens {
					if authenticate.TKN == tkn {
						ok = true
						break
					}
				}
				s.authOnce.Do(func() {
					if !ok {
						_ = s.quicConn.CloseWithError(AuthenticationFailed, "")
					}
					s.authOk = ok
					close(s.authCh)
				})
			case PacketType:
				var packet Packet
				packet, err = ReadPacketWithHead(commandHead, reader)
				if err != nil {
					return
				}
				return s.parsePacket(packet, "quic")
			case DissociateType:
				var disassociate Dissociate
				disassociate, err = ReadDissociateWithHead(commandHead, reader)
				if err != nil {
					return
				}
				if v, loaded := s.udpInputMap.LoadAndDelete(disassociate.ASSOC_ID); loaded {
					writeClosed := v.(*atomic.Bool)
					writeClosed.Store(true)
				}
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

type ServerAssocIdAddr string

func (a ServerAssocIdAddr) Network() string {
	return "ServerAssocIdAddr"
}

func (a ServerAssocIdAddr) String() string {
	return string(a)
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

var _ C.UDPPacket = &serverUDPPacket{}
var _ C.UDPPacketInAddr = &serverUDPPacket{}
