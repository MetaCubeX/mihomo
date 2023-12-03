package v5

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/atomic"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"github.com/puzpuzpuz/xsync/v3"
)

type ServerOption struct {
	HandleTcpFn func(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error
	HandleUdpFn func(addr socks5.Addr, packet C.UDPPacket, additions ...inbound.Addition) error

	Users                 map[[16]byte]string
	MaxUdpRelayPacketSize int
}

func NewServerHandler(option *ServerOption, quicConn quic.EarlyConnection, uuid uuid.UUID) common.ServerHandler {
	return &serverHandler{
		ServerOption: option,
		quicConn:     quicConn,
		uuid:         uuid,
		authCh:       make(chan struct{}),
		udpInputMap:  xsync.NewMapOf[uint16, *serverUDPInput](),
	}
}

type serverHandler struct {
	*ServerOption
	quicConn quic.EarlyConnection
	uuid     uuid.UUID

	authCh   chan struct{}
	authOk   atomic.Bool
	authUUID atomic.TypedValue[string]
	authOnce sync.Once

	udpInputMap *xsync.MapOf[uint16, *serverUDPInput]
}

func (s *serverHandler) AuthOk() bool {
	return s.authOk.Load()
}

func (s *serverHandler) HandleTimeout() {
	s.authOnce.Do(func() {
		_ = s.quicConn.CloseWithError(AuthenticationTimeout, "AuthenticationTimeout")
		s.authOk.Store(false)
		close(s.authCh)
	})
}

func (s *serverHandler) HandleMessage(message []byte) (err error) {
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
		return s.parsePacket(&packet, common.NATIVE)
	case HeartbeatType:
		var heartbeat Heartbeat
		heartbeat, err = ReadHeartbeatWithHead(commandHead, reader)
		if err != nil {
			return
		}
		heartbeat.BytesLen()
	}
	return
}

func (s *serverHandler) parsePacket(packet *Packet, udpRelayMode common.UdpRelayMode) (err error) {
	<-s.authCh
	if !s.authOk.Load() {
		return
	}
	var assocId uint16

	assocId = packet.ASSOC_ID

	input, _ := s.udpInputMap.LoadOrCompute(assocId, func() *serverUDPInput { return &serverUDPInput{} })
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
	}, inbound.WithInUser(s.authUUID.Load()))
}

func (s *serverHandler) HandleStream(conn *N.BufferedConn) (err error) {
	connect, err := ReadConnect(conn)
	if err != nil {
		return err
	}
	<-s.authCh
	if !s.authOk.Load() {
		return conn.Close()
	}

	err = s.HandleTcpFn(conn, connect.ADDR.SocksAddr(), inbound.WithInUser(s.authUUID.Load()))
	if err != nil {
		_ = conn.Close()
		return err
	}
	return
}

func (s *serverHandler) HandleUniStream(reader *bufio.Reader) (err error) {
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
			s.authOk.Store(authOk)
			s.authUUID.Store(authUUID.String())
			close(s.authCh)
		})
	case PacketType:
		var packet Packet
		packet, err = ReadPacketWithHead(commandHead, reader)
		if err != nil {
			return
		}
		return s.parsePacket(&packet, common.QUIC)
	case DissociateType:
		var disassociate Dissociate
		disassociate, err = ReadDissociateWithHead(commandHead, reader)
		if err != nil {
			return
		}
		if input, loaded := s.udpInputMap.LoadAndDelete(disassociate.ASSOC_ID); loaded {
			input.writeClosed.Store(true)
		}
	}
	return
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
