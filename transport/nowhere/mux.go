package nowhere

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
)

const (
	muxOpen      byte = 1
	muxData      byte = 2
	muxWindow    byte = 3
	muxFIN       byte = 4
	muxReset     byte = 5
	streamWindow      = 4 << 20
	connWindow        = 8 << 20
)

type muxFrame struct {
	kind    byte
	value   uint16
	id      uint32
	payload []byte
	written chan struct{}
}
type muxConn struct {
	net.Conn
	mu         sync.Mutex
	streams    map[uint32]*muxStream
	send, recv int
	sendPeak   int
	changed    chan struct{}
	done       chan struct{}
	queue      chan muxFrame
	onStream   func(*muxStream)
	incoming   chan struct{}
	active     int
	retiring   bool
	closeOnce  sync.Once
	lastActive time.Time
	windows    map[*muxStream]int // nil denotes connection credit; guarded by mu
	windowWake chan struct{}
}

func newMux(conn net.Conn, onStream func(*muxStream)) *muxConn {
	m := &muxConn{Conn: conn, streams: make(map[uint32]*muxStream), send: connWindow, recv: connWindow, changed: make(chan struct{}), done: make(chan struct{}), queue: make(chan muxFrame, 512), onStream: onStream, lastActive: time.Now()}
	m.windows = make(map[*muxStream]int)
	m.windowWake = make(chan struct{}, 1)
	m.sendPeak = connWindow
	m.incoming = make(chan struct{}, 4096)
	go m.writeLoop()
	go m.readLoop()
	go m.idleLoop()
	return m
}
func (m *muxConn) signal() { close(m.changed); m.changed = make(chan struct{}) }
func (m *muxConn) Close() error {
	m.closeOnce.Do(func() { close(m.done); _ = m.Conn.Close() })
	return nil
}
func (m *muxConn) control(f muxFrame) {
	select {
	case m.queue <- f:
	case <-m.done:
	default:
		_ = m.Close()
	}
}

// returnCredit and removeStream require mu. A stream may outlive its registry
// entry while the application drains DATA ordered before RESET or FIN.
func (m *muxConn) returnCredit(s *muxStream, n int) {
	m.recv += n
	m.windows[nil] += n / 1024
	if s != nil && m.streams[s.id] == s && !s.closed && !s.finRecv {
		s.recv += n
		m.windows[s] += n / 1024
	}
	select {
	case m.windowWake <- struct{}{}:
	default:
	}
}

func (m *muxConn) removeStream(s *muxStream) {
	if m.streams[s.id] == s {
		delete(m.streams, s.id)
	}
	delete(m.windows, s)
}
func (m *muxConn) idleLoop() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			m.mu.Lock()
			idle := m.active == 0 && time.Since(m.lastActive) > 30*time.Second
			m.mu.Unlock()
			if idle {
				_ = m.Close()
				return
			}
		}
	}
}
func (m *muxConn) stream(id uint32) *muxStream {
	s := &muxStream{m: m, id: id, send: streamWindow, recv: streamWindow, rd: deadline.MakePipeDeadline(), wd: deadline.MakePipeDeadline(), done: make(chan struct{}), localClosed: make(chan struct{})}
	m.streams[id] = s
	m.active++
	m.lastActive = time.Now()
	return s
}
func (m *muxConn) Open(id uint32) (*muxStream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return nil, net.ErrClosed
	default:
	}
	if m.retiring || len(m.streams) >= 4096 || m.streams[id] != nil {
		return nil, SetupError(FlowLimit)
	}
	s := m.stream(id)
	m.control(muxFrame{kind: muxOpen, id: id})
	return s, nil
}
func (m *muxConn) writeLoop() {
	defer m.Close()
	write := func(f muxFrame) error {
		var b [7]byte
		b[0] = f.kind
		binary.BigEndian.PutUint16(b[1:3], f.value)
		binary.BigEndian.PutUint32(b[3:], f.id)
		_ = m.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := writeFull(m.Conn, b[:]); err != nil {
			return err
		}
		if err := writeFull(m.Conn, f.payload); err != nil {
			return err
		}
		if f.written != nil {
			close(f.written)
		}
		return nil
	}
	for {
		select {
		case <-m.done:
			return
		case f := <-m.queue:
			m.mu.Lock()
			m.signal()
			m.mu.Unlock()
			if write(f) != nil {
				return
			}
		case <-m.windowWake:
			m.mu.Lock()
			windows := m.windows
			m.windows = make(map[*muxStream]int)
			m.mu.Unlock()
			for s, n := range windows {
				for n > 0 {
					var id uint32
					if s != nil {
						m.mu.Lock()
						current := m.streams[s.id] == s && !s.closed && !s.finRecv
						m.mu.Unlock()
						if !current {
							break
						}
						id = s.id
					}
					v := n
					if v > 65535 {
						v = 65535
					}
					if write(muxFrame{kind: muxWindow, value: uint16(v), id: id}) != nil {
						return
					}
					n -= v
				}
			}
		}
	}
}
func credit(n int) int { return (n + 1023) / 1024 * 1024 }
func (m *muxConn) readLoop() {
	defer m.Close()
	for {
		var b [7]byte
		if _, err := io.ReadFull(m.Conn, b[:]); err != nil {
			return
		}
		kind, value, id := b[0], int(binary.BigEndian.Uint16(b[1:3])), binary.BigEndian.Uint32(b[3:])
		if id > maxFlowID || id == 0 && kind != muxWindow {
			return
		}
		var data []byte
		if kind == muxData {
			if value == 0 {
				return
			}
			data = make([]byte, value)
			if _, err := io.ReadFull(m.Conn, data); err != nil {
				return
			}
		}
		m.mu.Lock()
		s := m.streams[id]
		valid := true
		var incoming *muxStream
		switch kind {
		case muxOpen:
			if m.onStream == nil || s != nil || len(m.streams) >= 4096 || value*1024 > 3*streamWindow {
				valid = false
				break
			}
			select {
			case m.incoming <- struct{}{}:
			default:
				valid = false
				break
			}
			if !valid {
				break
			}
			incoming = m.stream(id)
			incoming.send += value * 1024
		case muxData:
			n := credit(value)
			if s == nil || s.finRecv || n > s.recv || n > m.recv {
				valid = false
				break
			}
			s.recv -= n
			m.recv -= n
			if s.closed {
				m.returnCredit(nil, n)
			} else {
				s.buffers = append(s.buffers, data)
			}
		case muxWindow:
			if value == 0 {
				valid = false
				break
			}
			if id == 0 {
				m.send += value * 1024
				valid = m.send <= 4*connWindow
				if m.send > m.sendPeak {
					m.sendPeak = m.send
				}
			} else if s != nil && !s.closed {
				s.send += value * 1024
				valid = s.send <= 4*streamWindow
			}
		case muxFIN, muxReset:
			if value != 0 {
				valid = false
				break
			}
			if s != nil {
				s.finRecv = true
				if kind == muxReset {
					s.finSent = true
					if !s.closed && !s.reset {
						close(s.done)
					}
					s.reset = true
				}
				// Ordered DATA (including SetupResult) must remain readable even
				// when RESET follows before the application is scheduled.
				if s.finSent || kind == muxReset {
					m.removeStream(s)
				}
			}
		default:
			valid = false
		}
		m.lastActive = time.Now()
		m.signal()
		m.mu.Unlock()
		if !valid {
			return
		}
		if incoming != nil {
			go func() {
				defer func() { <-m.incoming }()
				m.onStream(incoming)
			}()
		}
	}
}
func (m *muxConn) discard(s *muxStream) {
	n := 0
	for _, b := range s.buffers {
		n += credit(len(b))
	}
	s.buffers = nil
	if n > 0 {
		m.returnCredit(nil, n)
	}
}

type muxStream struct {
	m                               *muxConn
	id                              uint32
	rmu, wmu                        sync.Mutex
	send, recv                      int
	buffers                         [][]byte
	offset                          int
	finRecv, finSent, closed, reset bool
	rd, wd                          deadline.PipeDeadline
	done                            chan struct{}
	localClosed                     chan struct{}
}

func (s *muxStream) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		s.m.mu.Lock()
		if s.closed {
			s.m.mu.Unlock()
			return 0, net.ErrClosed
		}
		if len(s.buffers) > 0 {
			b := s.buffers[0]
			n := copy(p, b[s.offset:])
			s.offset += n
			if s.offset == len(b) {
				s.buffers[0] = nil
				s.buffers = s.buffers[1:]
				s.offset = 0
				s.m.returnCredit(s, credit(len(b)))
			}
			s.m.mu.Unlock()
			return n, nil
		}
		if s.finRecv {
			s.m.mu.Unlock()
			return 0, io.EOF
		}
		changed := s.m.changed
		s.m.mu.Unlock()
		select {
		case <-s.m.done:
			return 0, net.ErrClosed
		case <-s.rd.Wait():
			return 0, os.ErrDeadlineExceeded
		case <-changed:
		}
	}
}
func (s *muxStream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		select {
		case <-s.wd.Wait():
			return total, os.ErrDeadlineExceeded
		default:
		}
		n := len(p)
		if n > 32768 {
			n = 32768
		}
		c := credit(n)
		s.m.mu.Lock()
		if s.closed || s.finSent {
			s.m.mu.Unlock()
			return total, net.ErrClosed
		}
		if s.send < c || s.m.send < c {
			changed := s.m.changed
			s.m.mu.Unlock()
			select {
			case <-s.m.done:
				return total, net.ErrClosed
			case <-s.wd.Wait():
				return total, os.ErrDeadlineExceeded
			case <-changed:
			}
			continue
		}
		s.send -= c
		s.m.send -= c
		f := muxFrame{kind: muxData, value: uint16(n), id: s.id, payload: append([]byte(nil), p[:n]...), written: make(chan struct{})}
		// Enqueue under the same lock as Close/RESET. A concurrent Close
		// must never put RESET ahead of this stream's last DATA frame.
		select {
		case s.m.queue <- f:
			s.m.mu.Unlock()
			// Once queued, DATA belongs to the carrier writer. A peer can
			// receive it and send a result followed by RESET before our socket
			// Write returns. Preserve that write's completion so the caller
			// can read the result; only local close may abandon the wait.
			select {
			case <-f.written:
				total += n
				p = p[n:]
			case <-s.m.done:
				return total, net.ErrClosed
			case <-s.localClosed:
				return total, net.ErrClosed
			case <-s.wd.Wait():
				_ = s.Close()
				return total, os.ErrDeadlineExceeded
			}
		default:
			s.send += c
			s.m.send += c
			changed := s.m.changed
			s.m.mu.Unlock()
			select {
			case <-s.m.done:
				return total, net.ErrClosed
			case <-s.done:
				return total, net.ErrClosed
			case <-s.wd.Wait():
				return total, os.ErrDeadlineExceeded
			case <-changed:
			}
		}
	}
	return total, nil
}
func (s *muxStream) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if !s.finSent && !s.closed {
		s.finSent = true
		s.m.control(muxFrame{kind: muxFIN, id: s.id})
		if s.finRecv {
			s.m.removeStream(s)
		}
		s.m.signal()
	}
	return nil
}
func (s *muxStream) Close() error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.localClosed)
		s.m.active--
		if !s.reset {
			close(s.done)
		}
		s.m.discard(s)
		delete(s.m.windows, s)
		if !s.finSent {
			s.m.control(muxFrame{kind: muxReset, id: s.id})
		}
		if s.finRecv {
			s.m.removeStream(s)
		}
		s.m.lastActive = time.Now()
		s.m.signal()
		if s.m.retiring && s.m.active == 0 {
			_ = s.m.Close()
		}
	}
	return nil
}
func (s *muxStream) LocalAddr() net.Addr                { return s.m.LocalAddr() }
func (s *muxStream) RemoteAddr() net.Addr               { return s.m.RemoteAddr() }
func (s *muxStream) SetDeadline(t time.Time) error      { s.rd.Set(t); s.wd.Set(t); return nil }
func (s *muxStream) SetReadDeadline(t time.Time) error  { s.rd.Set(t); return nil }
func (s *muxStream) SetWriteDeadline(t time.Time) error { s.wd.Set(t); return nil }
