package v4

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/atomic"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
	"github.com/Dreamacro/clash/transport/tuic/common"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
)

type ServerOption struct {
	HandleTcpFn func(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error
	HandleUdpFn func(addr socks5.Addr, packet C.UDPPacket, additions ...inbound.Addition) error

	Tokens                [][32]byte
	MaxUdpRelayPacketSize int
}

func NewServerHandler(option *ServerOption, quicConn quic.EarlyConnection, uuid uuid.UUID) common.ServerHandler {
	return &serverHandler{
		ServerOption: option,
		quicConn:     quicConn,
		uuid:         uuid,
		authCh:       make(chan struct{}),
	}
}

type serverHandler struct {
	*ServerOption
	quicConn quic.EarlyConnection
	uuid     uuid.UUID

	authCh   chan struct{}
	authOk   atomic.Bool
	authOnce sync.Once

	udpInputMap sync.Map
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
	buffer := bytes.NewBuffer(message)
	packet, err := ReadPacket(buffer)
	if err != nil {
		return
	}
	return s.parsePacket(&packet, common.NATIVE)
}

func (s *serverHandler) parsePacket(packet *Packet, udpRelayMode common.UdpRelayMode) (err error) {
	<-s.authCh
	if !s.authOk.Load() {
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
		inputConn:             nil,
		udpRelayMode:          udpRelayMode,
		maxUdpRelayPacketSize: s.MaxUdpRelayPacketSize,
		deferQuicConnFn:       nil,
		closeDeferFn:          nil,
		writeClosed:           writeClosed,
	}

	return s.HandleUdpFn(packet.ADDR.SocksAddr(), &serverUDPPacket{
		pc:     pc,
		packet: packet,
		rAddr:  N.NewCustomAddr("tuic", fmt.Sprintf("tuic-%s-%d", s.uuid, assocId), s.quicConn.RemoteAddr()), // for tunnel's handleUDPConn
	})
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
	_, err = buf.WriteTo(conn)
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
		for _, tkn := range s.Tokens {
			if authenticate.TKN == tkn {
				authOk = true
				break
			}
		}
		s.authOnce.Do(func() {
			if !authOk {
				_ = s.quicConn.CloseWithError(AuthenticationFailed, "AuthenticationFailed")
			}
			s.authOk.Store(authOk)
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
