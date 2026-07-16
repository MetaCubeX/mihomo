package muxcool

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
	"github.com/metacubex/mihomo/common/pool"
)

var ErrPacketTooLarge = fmt.Errorf("mux.cool packet exceeds %d bytes", MaxPayloadSize)

type packetMessage struct {
	payload []byte
	addr    net.Addr
}

func consumePacketMessage(p []byte, message packetMessage) (int, net.Addr, error) {
	n := copy(p, message.payload)
	_ = pool.Put(message.payload)
	return n, message.addr, nil
}

type packetSession struct {
	owner       sessionOwner
	id          uint16
	destination string
	port        uint16
	globalID    [8]byte

	writeMu sync.Mutex
	sentNew bool

	input         chan packetMessage
	done          chan struct{}
	closeOnce     sync.Once
	causeMu       sync.Mutex
	cause         error
	readDeadline  deadline.PipeDeadline
	writeDeadline deadline.PipeDeadline
}

func newPacketSession(
	ctx context.Context,
	owner sessionOwner,
	id uint16,
	destination string,
	port uint16,
	globalID [8]byte,
) (net.PacketConn, *packetSession) {
	s := makePacketSession(owner, id, destination, port, globalID)
	s.start(ctx)
	return s, s
}

func makePacketSession(
	owner sessionOwner,
	id uint16,
	destination string,
	port uint16,
	globalID [8]byte,
) *packetSession {
	s := &packetSession{
		owner:         owner,
		id:            id,
		destination:   destination,
		port:          port,
		globalID:      globalID,
		input:         make(chan packetMessage, 16),
		done:          make(chan struct{}),
		readDeadline:  deadline.MakePipeDeadline(),
		writeDeadline: deadline.MakePipeDeadline(),
	}
	return s
}

func (s *packetSession) start(ctx context.Context) {
	ctxDone := ctx.Done()
	if ctxDone == nil {
		return
	}
	go func() {
		select {
		case <-ctxDone:
			s.finish(context.Cause(ctx), true)
		case <-s.done:
		}
	}()
}

func (s *packetSession) ReadFrom(p []byte) (int, net.Addr, error) {
	message, err := s.readPacketMessage()
	if err != nil {
		return 0, nil, err
	}
	return consumePacketMessage(p, message)
}

func (s *packetSession) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	message, err := s.readPacketMessage()
	if err != nil {
		return nil, nil, nil, err
	}
	payload := message.payload
	put := func() {
		_ = pool.Put(payload)
	}
	return payload, put, message.addr, nil
}

func (s *packetSession) readPacketMessage() (packetMessage, error) {
	if message, ok := s.nextQueued(); ok {
		return message, nil
	}
	select {
	case message := <-s.input:
		return message, nil
	case <-s.done:
		if message, ok := s.nextQueued(); ok {
			return message, nil
		}
		return packetMessage{}, s.terminalCause()
	case <-s.readDeadline.Wait():
		return packetMessage{}, os.ErrDeadlineExceeded
	}
}

func (s *packetSession) nextQueued() (packetMessage, bool) {
	select {
	case message := <-s.input:
		return message, true
	default:
		return packetMessage{}, false
	}
}

func (s *packetSession) WriteTo(payload []byte, addr net.Addr) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	if len(payload) > MaxPayloadSize {
		return 0, ErrPacketTooLarge
	}
	target, err := splitPacketAddr(addr)
	if err != nil {
		return 0, err
	}

	s.writeMu.Lock()
	select {
	case <-s.done:
		s.writeMu.Unlock()
		return 0, s.terminalCause()
	case <-s.writeDeadline.Wait():
		s.writeMu.Unlock()
		return 0, os.ErrDeadlineExceeded
	default:
	}

	frame := Frame{
		SessionID:     s.id,
		Status:        StatusKeep,
		Option:        OptionData,
		Network:       NetworkUDP,
		Destination:   target.host,
		DestinationIP: target.ip,
		Port:          target.port,
		Payload:       payload,
	}
	if !s.sentNew {
		frame.Status = StatusNew
		frame.Destination = s.destination
		frame.DestinationIP = netip.Addr{}
		frame.Port = s.port
		frame.GlobalID = s.globalID
	}
	err = s.owner.writeFrame(frame)
	if err == nil {
		s.sentNew = true
	}
	s.writeMu.Unlock()
	if err != nil {
		s.finish(err, false)
		return 0, err
	}
	return len(payload), nil
}

func (s *packetSession) Close() error {
	s.finish(nil, true)
	return nil
}

func (s *packetSession) LocalAddr() net.Addr {
	return muxAddr("mux.cool-udp")
}

func (s *packetSession) SetDeadline(t time.Time) error {
	s.readDeadline.Set(t)
	s.writeDeadline.Set(t)
	return nil
}

func (s *packetSession) SetReadDeadline(t time.Time) error {
	s.readDeadline.Set(t)
	return nil
}

func (s *packetSession) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
}

func (s *packetSession) deliverFrame(frame Frame) error {
	decoded := decodedFrame{Frame: frame}
	if len(frame.Payload) > 0 {
		decoded.Payload = pool.Get(len(frame.Payload))[:len(frame.Payload)]
		copy(decoded.Payload, frame.Payload)
		decoded.payloadPooled = true
	}
	return s.deliverDecodedFrame(decoded)
}

func (s *packetSession) deliverDecodedFrame(decoded decodedFrame) error {
	frame := decoded.Frame
	if frame.Option&OptionData != 0 {
		if frame.Network != NetworkUDP || frame.Destination == "" {
			decoded.releasePayload()
			return protocolError("deliver UDP", errors.New("response frame is missing a UDP target"))
		}
		addr, err := makePacketAddr(frame.Destination, frame.Port)
		if err != nil {
			decoded.releasePayload()
			return protocolError("deliver UDP", err)
		}
		select {
		case s.input <- packetMessage{payload: frame.Payload, addr: addr}:
		case <-s.done:
			decoded.releasePayload()
			return net.ErrClosed
		}
	} else {
		decoded.releasePayload()
	}
	if frame.Status == StatusEnd || frame.Option&OptionError != 0 {
		var cause error
		if frame.Option&OptionError != 0 {
			cause = protocolError("remote session", errors.New("remote reported an error"))
		}
		s.finish(cause, false)
	}
	return nil
}

func (s *packetSession) closeCarrier(cause error) {
	s.finish(cause, false)
}

func (s *packetSession) finish(cause error, sendEnd bool) {
	s.closeOnce.Do(func() {
		s.writeMu.Lock()
		if sendEnd {
			_ = s.owner.writeFrame(Frame{SessionID: s.id, Status: StatusEnd})
		}
		s.causeMu.Lock()
		s.cause = cause
		s.causeMu.Unlock()
		close(s.done)
		s.writeMu.Unlock()
		s.owner.removeSession(s.id)
	})
}

func (s *packetSession) terminalCause() error {
	s.causeMu.Lock()
	defer s.causeMu.Unlock()
	if s.cause != nil {
		return s.cause
	}
	return net.ErrClosed
}

type domainPacketAddr struct {
	host string
	port uint16
}

func (a domainPacketAddr) Network() string { return "udp" }
func (a domainPacketAddr) String() string {
	return net.JoinHostPort(a.host, strconv.Itoa(int(a.port)))
}

func makePacketAddr(host string, port uint16) (net.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return nil, errors.New("scoped IPv6 addresses are not supported")
		}
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), port)), nil
	}
	if host == "" {
		return nil, errors.New("empty packet host")
	}
	return domainPacketAddr{host: host, port: port}, nil
}

type packetTarget struct {
	host string
	ip   netip.Addr
	port uint16
}

func splitPacketAddr(addr net.Addr) (packetTarget, error) {
	if addr == nil {
		return packetTarget{}, errors.New("nil packet address")
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if udpAddr.IP == nil || udpAddr.Port < 0 || udpAddr.Port > int(^uint16(0)) || udpAddr.Zone != "" {
			return packetTarget{}, fmt.Errorf("invalid UDP address %v", addr)
		}
		ip, valid := netip.AddrFromSlice(udpAddr.IP)
		if !valid {
			return packetTarget{}, fmt.Errorf("invalid UDP address %v", addr)
		}
		return packetTarget{ip: ip.Unmap(), port: uint16(udpAddr.Port)}, nil
	}
	host, rawPort, err := net.SplitHostPort(addr.String())
	if err != nil {
		return packetTarget{}, fmt.Errorf("parse packet address %q: %w", addr.String(), err)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || host == "" {
		return packetTarget{}, fmt.Errorf("invalid packet address %q", addr.String())
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		if ip.Zone() != "" {
			return packetTarget{}, errors.New("scoped IPv6 addresses are not supported")
		}
		return packetTarget{ip: ip.Unmap(), port: uint16(port)}, nil
	}
	return packetTarget{host: host, port: uint16(port)}, nil
}

var _ net.PacketConn = (*packetSession)(nil)
