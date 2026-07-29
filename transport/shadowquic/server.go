package shadowquic

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/jls-quic-go"
	"github.com/metacubex/jls-tls"
)

type ServerOption struct {
	HandleTcpFn func(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error
	HandleUdpFn func(addr socks5.Addr, packet C.UDPPacket, additions ...inbound.Addition) error

	TLSConfig  *tls.Config
	QUICConfig *quic.Config

	CongestionController  string
	SendBPS               uint64
	ReceiveBPS            uint64
	IgnoreClientBandwidth bool
	CWND                  int
	BBRProfile            string
}

type Server struct {
	option   *ServerOption
	listener *quic.EarlyListener
}

func NewServer(option *ServerOption, pc net.PacketConn) (*Server, error) {
	listener, err := quic.ListenEarly(pc, option.TLSConfig, option.QUICConfig)
	if err != nil {
		return nil, err
	}
	return &Server{option: option, listener: listener}, nil
}

func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		// Application streams may arrive before Brutal negotiation completes.
		SetCongestionController(conn, s.option.CongestionController, s.option.CWND, s.option.BBRProfile)
		state := newConnState(conn)
		go s.handleConnection(state)
	}
}

func (s *Server) Close() error {
	return s.listener.Close()
}

func (s *Server) handleConnection(state *connState) {
	for {
		stream, err := state.quicConn.AcceptStream(state.ctx)
		if err != nil {
			state.cancel()
			return
		}
		go s.handleStream(state, stream)
	}
}

func (s *Server) handleStream(state *connState, stream *quic.Stream) {
	conn := NewQuicStreamConn(stream, state.quicConn.LocalAddr(), state.quicConn.RemoteAddr(), nil)
	command, err := ReadCommand(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	switch command {
	case CommandConnect:
		target, err := ReadRequestAddr(conn)
		if err != nil {
			_ = conn.Close()
			return
		}
		if s.option.HandleTcpFn == nil {
			_ = conn.Close()
			return
		}
		if err = s.option.HandleTcpFn(conn, target, s.jlsAdditions(state)...); err != nil {
			_ = conn.Close()
		}
	case CommandAssociateDatagram, CommandAssociateStream:
		if _, err := ReadRequestAddr(conn); err != nil {
			_ = conn.Close()
			return
		}
		if s.option.HandleUdpFn == nil {
			_ = conn.Close()
			return
		}
		mode := udpModeDatagram
		if command == CommandAssociateStream {
			mode = udpModeStream
		}
		assoc := newAssociation(state, stream, mode)
		go s.handleAssociation(assoc)
	case CommandExtension:
		s.handleExtension(state, conn)
	case CommandBind, CommandAuthenticate:
		fallthrough
	default:
		_ = conn.Close()
	}
}

func (s *Server) handleBrutalNegotiation(state *connState, conn net.Conn) {
	rx, err := ReadBrutalNegotiationRequest(conn)
	if err != nil {
		return
	}
	rxAuto, err := s.configureBrutalCongestion(state.quicConn, rx)
	if err != nil {
		return
	}
	if err = WriteBrutalNegotiationResponse(conn, s.option.ReceiveBPS, rxAuto); err != nil {
		return
	}
}

func (s *Server) configureBrutalCongestion(quicConn *quic.Conn, clientRx uint64) (bool, error) {
	if s.option.ReceiveBPS > 0 && s.option.IgnoreClientBandwidth && clientRx == 0 {
		return false, errors.New("shadowquic: brutal negotiation failed")
	}
	if !(s.option.ReceiveBPS == 0 && s.option.IgnoreClientBandwidth) && clientRx > 0 {
		rx := clientRx
		if s.option.SendBPS > 0 && rx > s.option.SendBPS {
			rx = s.option.SendBPS
		}
		setBrutalCongestionController(quicConn, rx)
		return false, nil
	}
	SetCongestionController(quicConn, "bbr", s.option.CWND, s.option.BBRProfile)
	return true, nil
}

func (s *Server) handleExtension(state *connState, conn net.Conn) {
	defer conn.Close()

	opcode, err := ReadExtensionOpcode(conn)
	if err != nil {
		return
	}
	switch opcode {
	case extensionOpcodeMihomoBrutal:
		if state == nil || s.option == nil {
			_ = WriteExtensionErrorResult(conn, extensionErrNotAvailable, "")
			return
		}
		s.handleBrutalNegotiation(state, conn)
	case extensionOpcodeConn:
		subcommand, err := readExtensionSubcommand(conn)
		if err != nil {
			return
		}
		if subcommand != extensionConnGetStats {
			_ = WriteExtensionErrorResult(conn, extensionErrNotAvailable, "")
			return
		}
		_ = WriteExtensionConnStatsResult(conn, shadowQUICConnStats(state.quicConn))
	case extensionOpcodeUser:
		// Intentionally unsupported: the reference implementation grants remote
		// management to every username prefixed with "admin". Without an explicit
		// opt-in and persistence model, that would be a surprising control plane.
		// Keep returning NotAvailable unless such a model is deliberately added.
		if _, err := readExtensionSubcommand(conn); err != nil {
			return
		}
		_ = WriteExtensionErrorResult(conn, extensionErrNotAvailable, "")
	default:
		_ = WriteExtensionErrorResult(conn, extensionErrNotAvailable, "")
	}
}

func (s *Server) handleAssociation(assoc *association) {
	rAddr := N.NewCustomAddr("shadowquic", fmt.Sprintf("shadowquic-%p", assoc), assoc.parent.quicConn.RemoteAddr())
	additions := s.jlsAdditions(assoc.parent)
	for {
		select {
		case packet := <-assoc.input:
			s.option.HandleUdpFn(packet.socksAddr, &serverUDPPacket{
				assoc: assoc,
				data:  packet.data,
				rAddr: rAddr,
			}, additions...)
		case <-assoc.closed:
			return
		}
	}
}

func (s *Server) jlsAdditions(state *connState) []inbound.Addition {
	if user := s.jlsUser(state); user != "" {
		return []inbound.Addition{inbound.WithInUser(user)}
	}
	return nil
}

func (s *Server) jlsUser(state *connState) string {
	tlsState := state.quicConn.ConnectionState().TLS
	if tlsState.JLS.Status == tls.JLSAuthenticated {
		return tlsState.JLS.User
	}
	return ""
}

type serverUDPPacket struct {
	assoc *association
	data  []byte
	rAddr net.Addr
}

func (p *serverUDPPacket) Data() []byte {
	return p.data
}

func (p *serverUDPPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	return p.assoc.WriteTo(b, addr)
}

func (p *serverUDPPacket) Drop() {
	p.data = nil
}

func (p *serverUDPPacket) LocalAddr() net.Addr {
	return p.rAddr
}

func (p *serverUDPPacket) InAddr() net.Addr {
	return p.assoc.LocalAddr()
}

var _ C.UDPPacket = (*serverUDPPacket)(nil)
var _ C.UDPPacketInAddr = (*serverUDPPacket)(nil)
