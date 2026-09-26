package nowhere

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
	quic "github.com/metacubex/quic-go"
)

const packetBudget = 8 << 20

type fragmentKey struct{ flow, packet uint32 }
type assembly struct {
	count, total int
	size         int
	parts        [][]byte
	expires      time.Time
	invalid      bool
}
type quicSession struct {
	conn              *quic.Conn
	mu                sync.Mutex
	routes            map[uint32]*packetConn
	fragments         map[fragmentKey]*assembly
	queued, assembled int
	packetID          atomic.Uint32
	closeOnce         sync.Once
	pc                net.PacketConn
	readMu            sync.Mutex
	cancelRead        context.CancelFunc
	barriers          chan packetReadyRequest
	sends             chan *datagramSend
}

type packetReadyRequest struct {
	packet *packetConn
	result chan error
}

// One bounded sender per carrier isolates the uncancellable QUIC send queue
// from application deadlines. Never spawn a goroutine for each packet.
type datagramSend struct {
	id     uint32
	data   []byte
	close  bool
	cancel chan struct{}
	result chan error
}

func newQUICSession(conn *quic.Conn, pc net.PacketConn) *quicSession {
	q := &quicSession{conn: conn, pc: pc, routes: make(map[uint32]*packetConn), fragments: make(map[fragmentKey]*assembly), barriers: make(chan packetReadyRequest, 64), sends: make(chan *datagramSend, 64)}
	go q.sendLoop()
	return q
}

func (q *quicSession) sendLoop() {
	for {
		select {
		case <-q.conn.Context().Done():
			return
		case r := <-q.sends:
			select {
			case <-r.cancel:
				continue
			case <-q.conn.Context().Done():
				return
			default:
			}
			if r.close {
				var frame [4]byte
				binary.BigEndian.PutUint32(frame[:], r.id|2<<30)
				_ = q.conn.SendDatagram(frame[:])
			} else {
				r.result <- q.send(r.id, r.data, r.cancel)
			}
		}
	}
}

func (q *quicSession) notifyClose(id uint32) {
	select {
	case q.sends <- &datagramSend{id: id, close: true}:
	default: // CLOSE is best-effort; local cleanup must not wait for the carrier.
	}
}

func (p *packetConn) sendDatagram(b []byte) error {
	q := p.writeQ
	r := &datagramSend{id: p.id, data: append([]byte(nil), b...), cancel: make(chan struct{}), result: make(chan error, 1)}
	defer close(r.cancel)
	select {
	case q.sends <- r:
	case <-p.done:
		return net.ErrClosed
	case <-q.conn.Context().Done():
		return net.ErrClosed
	case <-p.wd.Wait():
		return os.ErrDeadlineExceeded
	}
	select {
	case err := <-r.result:
		return err
	case <-p.done:
		return net.ErrClosed
	case <-q.conn.Context().Done():
		return net.ErrClosed
	case <-p.wd.Wait():
		return os.ErrDeadlineExceeded
	}
}
func (q *quicSession) Close() error {
	q.closeOnce.Do(func() {
		_ = q.conn.CloseWithError(0, "")
		if q.pc != nil {
			_ = q.pc.Close()
		}
	})
	return nil
}
func (q *quicSession) run() {
	defer q.Close()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-q.conn.Context().Done():
				return
			case now := <-ticker.C:
				q.mu.Lock()
				q.expireFragments(now)
				q.mu.Unlock()
			}
		}
	}()
	for {
		select {
		case ready := <-q.barriers:
			err := q.drainBeforeReady()
			if err == nil {
				// The sole reader commits reception immediately after draining
				// old packets, before it can dispatch another datagram.
				err = ready.packet.activate()
			}
			ready.result <- err
			continue
		default:
		}
		ctx, cancel := context.WithCancel(q.conn.Context())
		q.readMu.Lock()
		q.cancelRead = cancel
		if len(q.barriers) > 0 {
			cancel()
		}
		q.readMu.Unlock()
		b, err := q.conn.ReceiveDatagram(ctx)
		q.readMu.Lock()
		q.cancelRead = nil
		q.readMu.Unlock()
		cancel()
		if err != nil {
			if errors.Is(err, context.Canceled) && q.conn.Context().Err() == nil {
				continue
			}
			return
		}
		q.receive(b)
	}
}

// ReceiveDatagram drains already queued packets before checking its context.
// Running this barrier in the sole reader prevents packets queued before
// local setup commitment from being admitted after the route becomes active.
func (q *quicSession) drainBeforeReady() error {
	ctx, cancel := context.WithCancel(q.conn.Context())
	cancel()
	until := time.Now().Add(10 * time.Second)
	for {
		b, err := q.conn.ReceiveDatagram(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) && q.conn.Context().Err() == nil {
				return nil
			}
			return err
		}
		q.receive(b)
		if time.Now().After(until) {
			return errors.New("nowhere: datagram readiness barrier overloaded")
		}
	}
}
func (p *packetConn) prepare() error {
	q := p.readQ
	if q == nil {
		return p.activate()
	}
	ready := make(chan error, 1)
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case q.barriers <- packetReadyRequest{packet: p, result: ready}:
	case <-q.conn.Context().Done():
		return net.ErrClosed
	case <-p.flow.done:
		return net.ErrClosed
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
	q.readMu.Lock()
	if q.cancelRead != nil {
		q.cancelRead()
	}
	q.readMu.Unlock()
	select {
	case err := <-ready:
		return err
	case <-q.conn.Context().Done():
		return net.ErrClosed
	case <-p.flow.done:
		return net.ErrClosed
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}
func (q *quicSession) receive(b []byte) {
	if len(b) < 4 {
		return
	}
	word := binary.BigEndian.Uint32(b)
	kind, id := word>>30, word&maxFlowID
	if id == 0 || kind == 3 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	p := q.routes[id]
	if p == nil || !p.ready.Load() {
		return
	}
	if kind == 2 {
		if len(b) == 4 && p.ready.Swap(false) {
			go p.Close()
		}
		return
	}
	if p.readQ != q {
		return
	}
	if kind == 0 {
		if len(b)-4 <= 65535 {
			q.deliver(p, b[4:])
		}
		return
	}
	if len(b) <= 12 {
		return
	}
	pid, index, count, total := binary.BigEndian.Uint32(b[4:]), int(b[8]), int(b[9]), int(binary.BigEndian.Uint16(b[10:]))
	if pid == 0 || count < 2 || index >= count || total == 0 || len(b)-12 > total {
		return
	}
	now := time.Now()
	q.expireFragments(now)
	key := fragmentKey{id, pid}
	a := q.fragments[key]
	if a == nil {
		if len(q.fragments) >= 64 {
			return
		}
		a = &assembly{count: count, total: total, parts: make([][]byte, count), expires: now.Add(10 * time.Second)}
		q.fragments[key] = a
	}
	if a.invalid {
		return
	}
	invalidate := func() { q.assembled -= a.size; a.size = 0; a.parts = nil; a.invalid = true }
	if a.count != count || a.total != total {
		invalidate()
		return
	}
	payload := b[12:]
	if a.parts[index] != nil {
		if !bytes.Equal(a.parts[index], payload) {
			invalidate()
		}
		return
	}
	if a.size+len(payload) > total || q.assembled+q.queued+len(payload) > packetBudget {
		invalidate()
		return
	}
	a.parts[index] = append([]byte(nil), payload...)
	a.size += len(payload)
	q.assembled += len(payload)
	if a.size != total {
		return
	}
	for _, part := range a.parts {
		if part == nil {
			return
		}
	}
	out := make([]byte, 0, total)
	for _, part := range a.parts {
		out = append(out, part...)
	}
	q.assembled -= a.size
	delete(q.fragments, key)
	q.deliver(p, out)
}
func (q *quicSession) expireFragments(now time.Time) {
	for key, a := range q.fragments {
		if !now.Before(a.expires) {
			q.assembled -= a.size
			delete(q.fragments, key)
		}
	}
}
func (q *quicSession) deliver(p *packetConn, b []byte) {
	charge := len(b) + 64
	if q.queued+q.assembled+charge > packetBudget {
		return
	}
	select {
	case p.packets <- append([]byte{}, b...):
		q.queued += charge
	default:
	}
}
func (q *quicSession) send(id uint32, b []byte, cancel <-chan struct{}) error {
	if len(b) > 65535 {
		return errors.New("nowhere: UDP packet exceeds 65535 bytes")
	}
	frame := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(frame, id)
	copy(frame[4:], b)
	err := q.conn.SendDatagram(frame)
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	chunk := int(tooLarge.MaxDatagramPayloadSize) - 12
	if chunk <= 0 {
		return err
	}
	count := (len(b) + chunk - 1) / chunk
	if count < 2 || count > 255 {
		return err
	}
	pid := q.packetID.Add(1)
	if pid == 0 {
		pid = q.packetID.Add(1)
	}
	for i, offset := 0, 0; offset < len(b); i++ {
		select {
		case <-cancel:
			return net.ErrClosed
		default:
		}
		n := len(b) - offset
		if n > chunk {
			n = chunk
		}
		part := make([]byte, 12+n)
		binary.BigEndian.PutUint32(part, id|1<<30)
		binary.BigEndian.PutUint32(part[4:], pid)
		part[8] = byte(i)
		part[9] = byte(count)
		binary.BigEndian.PutUint16(part[10:], uint16(len(b)))
		copy(part[12:], b[offset:offset+n])
		if err := q.conn.SendDatagram(part); err != nil {
			return err
		}
		offset += n
	}
	return nil
}

type packetConn struct {
	flow          *flowConn
	id            uint32
	address       net.Addr
	readQ, writeQ *quicSession
	packets       chan []byte
	done          chan struct{}
	ready         atomic.Bool
	stateMu       sync.Mutex
	once          sync.Once
	rmu, wmu      sync.Mutex
	rd, wd        deadline.PipeDeadline
}
type targetAddr string

func (a targetAddr) Network() string { return "udp" }
func (a targetAddr) String() string  { return string(a) }
func newPacket(flow *flowConn, id uint32, target string, readQ, writeQ *quicSession) (*packetConn, error) {
	p := &packetConn{flow: flow, id: id, address: targetAddr(target), readQ: readQ, writeQ: writeQ, packets: make(chan []byte, 64), done: make(chan struct{}), rd: deadline.MakePipeDeadline(), wd: deadline.MakePipeDeadline()}
	// mihomo's UDP NAT path expects IP replies as *net.UDPAddr. Keep domain
	// targets unresolved for transport users that delegate DNS to the peer.
	if addr, err := netip.ParseAddrPort(target); err == nil {
		p.address = net.UDPAddrFromAddrPort(addr)
	}
	if readQ != nil {
		readQ.mu.Lock()
		if readQ.routes[id] != nil {
			readQ.mu.Unlock()
			return nil, errProtocol
		}
		readQ.routes[id] = p
		readQ.mu.Unlock()
	}
	// Sending-only QUIC paths still need a CLOSE route.
	if writeQ != nil && writeQ != readQ {
		writeQ.mu.Lock()
		if writeQ.routes[id] != nil {
			writeQ.mu.Unlock()
			p.Close()
			return nil, errProtocol
		}
		writeQ.routes[id] = p
		writeQ.mu.Unlock()
	}
	return p, nil
}

// activate commits local receive readiness, not permission to relay payload.
// The server publishes READY only after this point and the handler starts
// relaying only after that write succeeds. Queues retain their normal bounds.
func (p *packetConn) activate() error {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	select {
	case <-p.done:
		return net.ErrClosed
	case <-p.flow.done:
		return net.ErrClosed
	default:
	}
	p.ready.Store(true)
	return nil
}

func (p *packetConn) start() error {
	if err := p.prepare(); err != nil {
		return err
	}
	go func() {
		select {
		case <-p.flow.done:
			p.Close()
		case <-p.done:
		}
	}()
	for _, l := range p.flow.lanes() {
		if l.q != nil {
			// The reference peer finishes UDP control streams after setup.
			// DATAGRAM CLOSE and carrier failure own the route lifetime.
			go func(l *lane) {
				select {
				case <-l.q.conn.Context().Done():
					p.Close()
				case <-p.done:
				}
			}(l)
		}
	}
	return nil
}
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	if p.readQ != nil {
		select {
		case <-p.done:
			return 0, nil, net.ErrClosed
		case <-p.readQ.conn.Context().Done():
			return 0, nil, net.ErrClosed
		case <-p.rd.Wait():
			return 0, nil, os.ErrDeadlineExceeded
		case data := <-p.packets:
			p.readQ.mu.Lock()
			p.readQ.queued -= len(data) + 64
			p.readQ.mu.Unlock()
			n := copy(b, data)
			if n < len(data) {
				return n, p.address, io.ErrShortBuffer
			}
			return n, p.address, nil
		}
	}
	var h [2]byte
	if _, err := io.ReadFull(p.flow, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > len(b) {
		data := make([]byte, n)
		if _, err := io.ReadFull(p.flow, data); err != nil {
			return 0, nil, err
		}
		return copy(b, data), p.address, io.ErrShortBuffer
	}
	_, err := io.ReadFull(p.flow, b[:n])
	if err != nil {
		return 0, nil, err
	}
	return n, p.address, nil
}
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if addr == nil || addr.String() != p.address.String() {
		return 0, errors.New("nowhere: UDP flow is bound to its setup target")
	}
	if len(b) > 65535 {
		return 0, errors.New("nowhere: UDP packet exceeds 65535 bytes")
	}
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case <-p.wd.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	var err error
	if p.writeQ != nil {
		err = p.sendDatagram(b)
	} else {
		frame := make([]byte, 2+len(b))
		binary.BigEndian.PutUint16(frame, uint16(len(b)))
		copy(frame[2:], b)
		err = writeFull(p.flow, frame)
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
func (p *packetConn) Close() error {
	p.once.Do(func() {
		p.stateMu.Lock()
		close(p.done)
		p.ready.Store(false)
		p.stateMu.Unlock()
		for i, q := range []*quicSession{p.readQ, p.writeQ} {
			if q == nil || i == 1 && q == p.readQ {
				continue
			}
			q.mu.Lock()
			if q.routes[p.id] == p {
				delete(q.routes, p.id)
				for key, a := range q.fragments {
					if key.flow == p.id {
						q.assembled -= a.size
						delete(q.fragments, key)
					}
				}
			}
			q.mu.Unlock()
			q.notifyClose(p.id)
		}
		if p.readQ != nil {
			p.readQ.mu.Lock()
			for {
				select {
				case b := <-p.packets:
					p.readQ.queued -= len(b) + 64
				default:
					p.readQ.mu.Unlock()
					p.flow.Close()
					return
				}
			}
		}
		p.flow.Close()
	})
	return nil
}
func (p *packetConn) LocalAddr() net.Addr { return p.flow.LocalAddr() }
func (p *packetConn) SetDeadline(t time.Time) error {
	p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}
func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.rd.Set(t)
	return p.flow.SetReadDeadline(t)
}
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	p.wd.Set(t)
	return p.flow.SetWriteDeadline(t)
}
