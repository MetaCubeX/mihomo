package miu

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/metacubex/sing/common/metadata"
)

var (
	errDownEnd = errors.New("miu: end of downlink")
	errSwapped = errors.New("miu: lane replaced")
)

// stream is the client side of one stream, as a net.Conn. It owns its lane until both directions have
// ended, then hands it back to the pool. Closing it earlier aborts the stream: RESET goes out, the
// downlink is read up to the server's END and dropped, and the lane is pooled all the same.
type stream struct {
	c      *Client
	remote net.Addr
	// open is what starts the stream: the OPEN frame. It leaves together with the first payload, or
	// alone after firstPayloadWait.
	open  []byte
	lane  atomic.Pointer[lane]
	state streamState
	timer *time.Timer

	// rmu guards the read side: Read, and the drain that follows Close.
	rmu       sync.Mutex
	downScan  recScan
	downEnded bool
	rerr      error

	// wmu guards the write side: Write, CloseWrite, the deferred OPEN, a replay and the abort.
	// Lock order: rmu, wmu, mu.
	wmu     sync.Mutex
	opened  bool // OPEN has been sent
	pkt     uint32
	upScan  recScan
	raw     bool // the uplink is in its raw phase
	upEnded bool // END has been sent
	werr    error
	history []byte // the uplink so far, kept while a replay is still possible
	frames  []byte // scratch

	mu sync.Mutex
	// replayable: the lane came from the pool, nothing has been received and at most replayLimit sent.
	// If the lane turns out to be dead the stream starts over on a new one. swapping: that is underway.
	replayable bool
	swapping   bool
	sawDown    bool // a downlink frame of this stream has arrived
	upDone     bool
	downDone   bool
	released   bool // the lane is no longer the stream's
	rd, wd     time.Time
	laneUsed   bool // the lane had carried a stream before this one

	seenDown atomic.Bool // sawDown, readable without mu
	closed   atomic.Bool
}

func (c *Client) open(ctx context.Context, open []byte, destination M.Socksaddr) (*stream, error) {
	l, pooled, used, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	s := &stream{c: c, remote: destination, open: open, pkt: 1, replayable: pooled, laneUsed: used}
	s.lane.Store(l)
	// UDP streams never use raw segments; neither does a lane that cannot carry them.
	dead := isUoT(destination) || !l.canRaw
	s.upScan = recScan{st: &s.state, dead: dead}
	s.downScan = recScan{st: &s.state, dead: dead}
	s.timer = time.AfterFunc(firstPayloadWait, s.flushOpen)
	return s, nil
}

// ---- the write side ----

// Write sends p up the stream. Each call (up to maxBatch bytes of it) is one batch: a "packet" for the
// shaping while the stream is in its DATA phase, a raw segment once the inner TLS 1.3 handshake is past
// and the batch is large enough.
func (s *stream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	total := 0
	for {
		switch {
		case s.closed.Load():
			return total, net.ErrClosed
		case s.upEnded:
			return total, io.ErrClosedPipe
		case s.werr != nil:
			return total, s.werr
		case len(p) == 0:
			return total, nil
		}
		k := len(p)
		if !s.raw {
			k = minInt(k, maxBatch)
		}
		if err := s.send(p[:k]); err != nil {
			s.werr = err
			return total, err
		}
		total += k
		p = p[k:]
	}
}

// send writes one batch. Caller holds wmu.
func (s *stream) send(b []byte) error {
	l := s.lane.Load()
	if s.raw {
		var err error
		if len(b) >= rawMin {
			err = l.writeRaw(b)
		} else {
			s.frames = appendData(s.frames[:0], b)
			err = l.writeUnshaped(s.frames)
		}
		if err != nil {
			l.close()
		}
		return err
	}
	ready := s.upScan.feed(b)
	if err := s.sendPacket(l, b); err == nil {
		s.remember(b)
	} else {
		if !s.replay(l) {
			l.close()
			return err
		}
		l = s.lane.Load()
		if err := s.sendPacket(l, b); err != nil {
			l.close()
			return err
		}
	}
	// The record header that makes the direction ready went out as DATA; raw segments start with the
	// next batch, provided the peer can take them.
	if ready && l.peerRaw.Load() {
		s.raw = true
	}
	return nil
}

// sendPacket sends b as the next shaped packet, preceded by OPEN if that is still to go.
func (s *stream) sendPacket(l *lane, b []byte) error {
	s.frames = s.frames[:0]
	if !s.opened {
		s.frames = append(s.frames, s.open...)
	}
	s.frames = appendData(s.frames, b)
	if err := l.writePacket(s.pkt, s.frames); err != nil {
		return err
	}
	s.opened = true
	s.pkt++
	return nil
}

// remember keeps b for a possible replay. Caller holds wmu.
func (s *stream) remember(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.replayable {
		return
	}
	if s.sawDown || len(s.history)+len(b) > replayLimit {
		s.replayable, s.history = false, nil
		return
	}
	s.history = append(s.history, b...)
}

// flushOpen sends OPEN on its own when the application has not written anything within
// firstPayloadWait: a protocol in which the server speaks first must not wait for the client.
func (s *stream) flushOpen() {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.opened || s.upEnded || s.werr != nil || s.closed.Load() {
		return
	}
	l := s.lane.Load()
	if err := s.sendPacket(l, nil); err != nil && !s.replay(l) {
		l.close()
		s.werr = err
	}
}

// CloseWrite ends the uplink (a half-close). The downlink keeps going.
func (s *stream) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	switch {
	case s.closed.Load():
		return net.ErrClosed
	case s.upEnded:
		return nil
	case s.werr != nil:
		return s.werr
	}
	s.timer.Stop()
	s.upEnded = true
	// Like shutdown(2), the half-close is not subject to the write deadline. (crypto/tls, when it is
	// the inner connection, leaves an expired one behind after sending its close_notify.)
	s.mu.Lock()
	s.wd = time.Time{}
	l := s.lane.Load()
	_ = l.conn.SetWriteDeadline(time.Time{})
	s.mu.Unlock()
	if err := s.sendEnd(l, frEnd); err != nil && !s.replay(l) {
		l.close()
		s.werr = err
		return err
	}
	s.finish(true, false)
	return nil
}

// sendEnd ends the uplink with END or RESET, preceded by OPEN if that is still to go. Nothing here is
// shaped: END has to be the last byte of the direction. A PAD after it would reach the server while it
// already considers the stream over. Caller holds wmu.
func (s *stream) sendEnd(l *lane, typ byte) error {
	var b []byte
	if !s.opened {
		b = append(b, s.open...)
	}
	if err := l.writeUnshaped(appendFrame(b, typ, nil)); err != nil {
		return err
	}
	s.opened = true
	return nil
}

// replay starts the stream over on a freshly dialed lane after old has failed: OPEN, everything sent so
// far, and END if the uplink had already ended. It is done at most once, and only while the lane came
// from the pool and nothing of the downlink has been seen — the case of a pooled lane that died without
// the client noticing. The other idle lanes went through the same network, so they are dropped too.
// It reports whether the stream now has a working lane. Caller holds wmu.
func (s *stream) replay(old *lane) bool {
	s.mu.Lock()
	if s.lane.Load() != old {
		s.mu.Unlock()
		return true // the other side of the stream has already done it
	}
	if !s.replayable || s.sawDown || s.closed.Load() {
		s.mu.Unlock()
		return false
	}
	s.replayable, s.swapping = false, true
	s.mu.Unlock()

	old.close()
	s.c.closeIdle()
	ctx, cancel := context.WithTimeout(context.Background(), defaultDialTimeout)
	nl, err := s.c.dial(ctx)
	cancel()
	if err == nil {
		// The new lane is fresh: the packet numbering starts over.
		err = nl.writePacket(1, appendData(append([]byte(nil), s.open...), s.history))
		if err == nil && s.upEnded {
			err = nl.writeFrame(frEnd, nil)
		}
		if err != nil {
			nl.close()
		}
	}
	s.history = nil

	s.mu.Lock()
	defer s.mu.Unlock()
	s.swapping = false
	if err != nil {
		return false
	}
	if s.closed.Load() {
		_ = nl.conn.SetDeadline(time.Now().Add(abortDrain))
	} else {
		if !s.rd.IsZero() {
			_ = nl.conn.SetReadDeadline(s.rd)
		}
		if !s.wd.IsZero() {
			_ = nl.conn.SetWriteDeadline(s.wd)
		}
	}
	s.lane.Store(nl)
	s.opened, s.pkt = true, 2
	nl.event("replay")
	return true
}

// ---- the read side ----

func (s *stream) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		l := s.lane.Load()
		switch {
		case s.closed.Load():
			return 0, net.ErrClosed
		case s.downEnded:
			return 0, io.EOF
		case s.rerr != nil:
			return 0, s.rerr
		}
		n, err := s.readOn(l, p)
		if n > 0 {
			return n, nil
		}
		switch {
		case err == errDownEnd:
			s.downEnded = true
			s.finish(false, true)
			return 0, io.EOF
		case errors.Is(err, os.ErrDeadlineExceeded) && !l.closed.Load():
			// A deadline set by the application, or the wake-up from Close. The read cursor is intact.
			if s.closed.Load() {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		// The lane failed. A dead pooled lane is replaced once; make sure a writer blocked on it lets go.
		l.close()
		if !s.seenDown.Load() {
			s.wmu.Lock()
			ok := s.replay(l)
			s.wmu.Unlock()
			if ok {
				continue
			}
		}
		if err == errSwapped || err == io.EOF {
			err = io.ErrUnexpectedEOF // the lane ended, not the stream
		}
		s.rerr = err
		return 0, err
	}
}

// readOn reads downlink payload from l into p. It returns errDownEnd at the server's END.
func (s *stream) readOn(l *lane, p []byte) (int, error) {
	for {
		if l.pending() {
			data := l.dataLeft > 0
			n, err := l.readPayload(p)
			if n > 0 && data {
				// The inner ServerHello is in the downlink's DATA: the uplink learns from it whether
				// the inner connection is TLS 1.3.
				s.downScan.feed(p[:n])
			}
			if n > 0 || err != nil {
				return n, err
			}
			continue
		}
		typ, payload, err := l.next()
		if err != nil {
			return 0, err
		}
		switch typ {
		case frData, frRaw:
			if !s.noteDown(l) {
				return 0, errSwapped
			}
		case frEnd:
			if len(payload) != 0 {
				return 0, errors.New("miu: bad END frame")
			}
			if !s.noteDown(l) {
				return 0, errSwapped
			}
			return 0, errDownEnd
		default:
			if err := l.control(typ, payload); err != nil {
				return 0, err
			}
		}
	}
}

// noteDown records that the downlink has begun, which rules a replay out. It reports false when a
// replay got there first: l is then no longer the stream's lane.
func (s *stream) noteDown(l *lane) bool {
	if s.seenDown.Load() {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.swapping || s.lane.Load() != l {
		return false
	}
	s.sawDown = true
	s.seenDown.Store(true)
	return true
}

// ---- the end of a stream ----

// finish records the end of a direction. Once both have ended the lane goes back to the pool.
func (s *stream) finish(up, down bool) {
	s.mu.Lock()
	s.upDone = s.upDone || up
	s.downDone = s.downDone || down
	if s.released || !s.upDone || !s.downDone {
		s.mu.Unlock()
		return
	}
	s.released = true
	l := s.lane.Load()
	s.mu.Unlock()
	if l.closed.Load() || l.conn.SetDeadline(time.Time{}) != nil {
		l.close()
		return
	}
	s.c.put(l, true)
}

// Close ends the stream. If a direction is still open this is an abort: the server is sent RESET and the
// rest of the downlink is discarded in the background, after which the lane returns to the pool. Aborts
// are common (an application closing a connection, a speed test that has read enough), and giving up a
// lane for each of them would leave the pool without warm connections.
func (s *stream) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.timer.Stop()
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return nil
	}
	// Wake a blocked Read now; give a blocked Write until the end of the drain.
	l := s.lane.Load()
	_ = l.conn.SetReadDeadline(time.Now())
	_ = l.conn.SetWriteDeadline(time.Now().Add(abortDrain))
	s.mu.Unlock()
	go s.abort()
	return nil
}

func (s *stream) abort() {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	s.wmu.Lock()
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		s.wmu.Unlock()
		return
	}
	s.released = true
	s.mu.Unlock()

	l := s.lane.Load()
	deadline := time.Now().Add(abortDrain)
	clean := s.rerr == nil && s.werr == nil && !l.closed.Load()
	opened, reset := s.opened, false
	// A stream whose OPEN never left has nothing to take back. Otherwise: RESET while the downlink is
	// still running — in place of END, or after it when the application half-closed first and then
	// closed, the usual order — and a plain END when only the uplink was left open.
	if clean && opened && !(s.upEnded && s.downEnded) {
		_ = l.conn.SetWriteDeadline(deadline)
		typ := byte(frEnd)
		if !s.downEnded {
			typ, reset = frReset, true
		}
		clean = l.writeFrame(typ, nil) == nil
	}
	s.wmu.Unlock()
	if clean && opened && !s.downEnded {
		_ = l.conn.SetReadDeadline(deadline)
		clean = l.discardToEnd() == nil
	}
	if !clean || l.conn.SetDeadline(time.Time{}) != nil {
		l.close()
		return
	}
	if reset {
		l.event("reset")
	}
	s.c.put(l, opened || s.laneUsed)
}

// ---- the rest of net.Conn ----

func (s *stream) LocalAddr() net.Addr  { return s.lane.Load().conn.LocalAddr() }
func (s *stream) RemoteAddr() net.Addr { return s.remote }

func (s *stream) SetDeadline(t time.Time) error {
	return s.setDeadline(&t, &t)
}

func (s *stream) SetReadDeadline(t time.Time) error {
	return s.setDeadline(&t, nil)
}

func (s *stream) SetWriteDeadline(t time.Time) error {
	return s.setDeadline(nil, &t)
}

// setDeadline applies the deadlines to the lane while the stream still owns it. A read that times out
// can be retried; a write that times out breaks the stream (the TLS record may be half written).
func (s *stream) setDeadline(rd, wd *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	if rd != nil {
		s.rd = *rd
	}
	if wd != nil {
		s.wd = *wd
	}
	if s.released {
		return nil
	}
	conn := s.lane.Load().conn
	if rd != nil {
		_ = conn.SetReadDeadline(*rd)
	}
	if wd != nil {
		_ = conn.SetWriteDeadline(*wd)
	}
	return nil
}

var _ interface {
	net.Conn
	CloseWrite() error
} = (*stream)(nil)
