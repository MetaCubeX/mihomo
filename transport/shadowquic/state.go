package shadowquic

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/jls-quic-go"
)

const maxPendingPacketsPerID = 32

type udpMode uint8

const (
	udpModeDatagram udpMode = iota
	udpModeStream
)

type receivedPacket struct {
	data      []byte
	addr      net.Addr
	socksAddr socks5.Addr
}

type connState struct {
	quicConn *quic.Conn
	ctx      context.Context
	cancel   context.CancelFunc

	mu         sync.Mutex
	nextID     uint16
	activeSend map[uint16]struct{}
	recv       map[uint16]*recvSlot
}

type recvSlot struct {
	ready   chan struct{}
	target  *recvTarget
	pending [][]byte
}

type recvTarget struct {
	assoc *association
	addr  socks5.Addr
	net   net.Addr
}

func newConnState(quicConn *quic.Conn) *connState {
	ctx, cancel := context.WithCancel(quicConn.Context())
	state := &connState{
		quicConn:   quicConn,
		ctx:        ctx,
		cancel:     cancel,
		activeSend: make(map[uint16]struct{}),
		recv:       make(map[uint16]*recvSlot),
	}
	go state.handleDatagrams()
	go state.handleUniStreams()
	go func() {
		<-quicConn.Context().Done()
		cancel()
	}()
	return state
}

func (s *connState) closed() bool {
	select {
	case <-s.ctx.Done():
		return true
	default:
		return false
	}
}

func (s *connState) closeWithError(code quic.ApplicationErrorCode, message string) error {
	s.cancel()
	return s.quicConn.CloseWithError(code, message)
}

func (s *connState) handleDatagrams() {
	for {
		message, err := s.quicConn.ReceiveDatagram(s.ctx)
		if err != nil {
			s.cancel()
			return
		}
		id, payload, err := DecodeDatagram(message)
		if err != nil {
			continue
		}
		s.feedDatagram(id, payload)
	}
}

func (s *connState) handleUniStreams() {
	for {
		stream, err := s.quicConn.AcceptUniStream(s.ctx)
		if err != nil {
			s.cancel()
			return
		}
		go s.handleUniStream(stream)
	}
}

func (s *connState) handleUniStream(stream *quic.ReceiveStream) {
	defer stream.CancelRead(0)

	id, err := ReadUint16(stream)
	if err != nil {
		return
	}
	target, err := s.waitRecvTarget(id)
	if err != nil {
		return
	}

	for {
		length, err := ReadUint16(stream)
		if err != nil {
			return
		}
		payload := make([]byte, int(length))
		if _, err = io.ReadFull(stream, payload); err != nil {
			return
		}
		target.assoc.deliver(receivedPacket{
			data:      payload,
			addr:      target.net,
			socksAddr: target.addr,
		})
	}
}

func (s *connState) feedDatagram(id uint16, payload []byte) {
	s.mu.Lock()
	slot := s.recv[id]
	if slot != nil && slot.target != nil {
		target := slot.target
		s.mu.Unlock()
		target.assoc.deliver(receivedPacket{
			data:      payload,
			addr:      target.net,
			socksAddr: target.addr,
		})
		return
	}
	if slot == nil {
		slot = &recvSlot{ready: make(chan struct{})}
		s.recv[id] = slot
	}
	if len(slot.pending) < maxPendingPacketsPerID {
		packet := make([]byte, len(payload))
		copy(packet, payload)
		slot.pending = append(slot.pending, packet)
	}
	s.mu.Unlock()
}

func (s *connState) waitRecvTarget(id uint16) (*recvTarget, error) {
	for {
		s.mu.Lock()
		slot := s.recv[id]
		if slot == nil {
			slot = &recvSlot{ready: make(chan struct{})}
			s.recv[id] = slot
		}
		if slot.target != nil {
			target := slot.target
			s.mu.Unlock()
			return target, nil
		}
		ready := slot.ready
		s.mu.Unlock()

		select {
		case <-ready:
		case <-s.ctx.Done():
			return nil, net.ErrClosed
		}
	}
}

func (s *connState) storeRecv(id uint16, assoc *association, addr socks5.Addr) {
	netAddr := AddrToNetAddr(addr)

	s.mu.Lock()
	slot := s.recv[id]
	if slot == nil {
		slot = &recvSlot{ready: make(chan struct{})}
		s.recv[id] = slot
	}
	wasPending := slot.target == nil
	slot.target = &recvTarget{assoc: assoc, addr: addr, net: netAddr}
	pending := slot.pending
	slot.pending = nil
	if wasPending {
		close(slot.ready)
	}
	s.mu.Unlock()

	for _, packet := range pending {
		assoc.deliver(receivedPacket{
			data:      packet,
			addr:      netAddr,
			socksAddr: addr,
		})
	}
}

func (s *connState) removeRecvIDs(assoc *association, ids map[uint16]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id := range ids {
		slot := s.recv[id]
		if slot != nil && slot.target != nil && slot.target.assoc == assoc {
			delete(s.recv, id)
		}
	}
}

func (s *connState) allocSendID() (uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	start := s.nextID
	for {
		id := s.nextID
		s.nextID++
		if _, exists := s.activeSend[id]; !exists {
			s.activeSend[id] = struct{}{}
			return id, nil
		}
		if s.nextID == start {
			return 0, errorsTooManyUDPContexts{}
		}
	}
}

func (s *connState) releaseSendIDs(ids map[uint16]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id := range ids {
		delete(s.activeSend, id)
	}
}

type errorsTooManyUDPContexts struct{}

func (errorsTooManyUDPContexts) Error() string {
	return "shadowquic: too many udp contexts"
}
