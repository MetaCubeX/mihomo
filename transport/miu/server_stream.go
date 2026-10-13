package miu

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/transport/anytls/pipe"
)

// upQueue is how many pieces of uplink payload may wait for the handler.
const upQueue = 16

var errReset = errors.New("miu: stream reset by the client")

// serverStream is the server side of one stream, as a net.Conn for the handler.
//
// The uplink is queued by the lane's read loop and taken from the queue by the handler's Read. The queue
// is short, so the loop reads from the client no faster than the handler consumes — but it does not
// stall on a handler that has yet to start reading (one that is still connecting to the destination),
// which keeps a RESET from waiting behind the first bytes of the stream.
// The downlink is written by the handler: DATA frames first, following the inner TLS records on the
// way, then raw segments once the inner TLS 1.3 handshake is past and the client can take them.
type serverStream struct {
	l    *lane
	idle time.Duration // how long the lane is kept once the stream has ended

	// The uplink. up carries pooled buffers and is closed at the client's END; stop is closed when
	// reading is over for another reason (stopErr): Close, a RESET, or the lane has gone away.
	up       chan []byte
	stop     chan struct{}
	stopErr  error
	stopOnce sync.Once
	upEnded  bool // END or RESET has arrived; owned by the lane's read loop

	// rmu guards the handler's side of the uplink.
	rmu   sync.Mutex
	chunk []byte // the buffer being read, to go back to the pool
	rest  []byte // what is left of it
	rd    pipe.PipeDeadline

	// wmu guards the downlink.
	wmu       sync.Mutex
	state     streamState
	scan      recScan
	pkt       uint32 // packets sent so far, for the shaping
	raw       bool   // the downlink is in its raw phase
	downEnded bool   // END has been sent (or could not be)
	frames    []byte // scratch
	wd        pipe.PipeDeadline

	mu       sync.Mutex
	upDone   bool
	downDone bool
	done     chan struct{} // closed once the downlink has ended
}

// newServerStream starts a stream on l. udp: the stream carries UDP packets, which never go out as raw
// segments; neither does anything on a lane that cannot carry them.
func newServerStream(l *lane, idle time.Duration, udp bool) *serverStream {
	s := &serverStream{
		l:    l,
		idle: idle,
		up:   make(chan []byte, upQueue),
		stop: make(chan struct{}),
		rd:   pipe.MakePipeDeadline(),
		wd:   pipe.MakePipeDeadline(),
		done: make(chan struct{}),
	}
	s.scan = recScan{st: &s.state, dead: udp || !l.canRaw}
	return s
}

// ---- the uplink (called by the lane's read loop) ----

// push queues a piece of uplink payload for the handler and takes over the pooled buffer b. Once the
// handler has stopped reading the payload is dropped: the lane's uplink still has to be read up to its
// END for the lane to stay usable.
func (s *serverStream) push(b []byte) {
	select {
	case s.up <- b:
	case <-s.stop:
		_ = pool.Put(b)
	}
}

// endUplink records the client's END: the handler reads what is queued, then io.EOF.
func (s *serverStream) endUplink() {
	if s.upEnded {
		return // a RESET after the END
	}
	s.upEnded = true
	close(s.up)
	s.finish(true, false)
}

// reset aborts the stream at the client's request: the handler's Read fails, nothing more is written
// and the downlink ends with END — after the raw segment being written, if there is one, so the byte
// count on the lane stays right.
func (s *serverStream) reset() {
	s.stopRead(errReset)
	_ = s.endDownlink()
}

// laneClosed wakes a handler blocked in Read when the lane has gone away under the stream.
func (s *serverStream) laneClosed() {
	s.mu.Lock()
	ended := s.upDone
	s.mu.Unlock()
	if !ended {
		s.stopRead(io.ErrUnexpectedEOF)
	}
}

func (s *serverStream) stopRead(err error) {
	s.stopOnce.Do(func() {
		s.stopErr = err
		close(s.stop)
	})
}

// ---- the handler's side ----

func (s *serverStream) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for len(s.rest) == 0 {
		if s.chunk != nil {
			_ = pool.Put(s.chunk)
			s.chunk = nil
		}
		select {
		case <-s.stop:
			return 0, s.stopErr
		case <-s.rd.Wait():
			return 0, os.ErrDeadlineExceeded
		default:
		}
		select {
		case b, ok := <-s.up:
			if !ok {
				return 0, io.EOF
			}
			s.chunk, s.rest = b, b
		case <-s.stop:
			return 0, s.stopErr
		case <-s.rd.Wait():
			return 0, os.ErrDeadlineExceeded
		}
	}
	n := copy(p, s.rest)
	s.rest = s.rest[n:]
	return n, nil
}

// Write sends p down the stream. Each call (up to maxBatch bytes of it) is one batch: a "packet" for
// the shaping while the stream is in its DATA phase, a raw segment once it is past that and the batch
// is large enough.
func (s *serverStream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		select {
		case <-s.wd.Wait():
			return total, os.ErrDeadlineExceeded
		default:
		}
		if s.downEnded {
			return total, io.ErrClosedPipe
		}
		k := len(p)
		if !s.raw {
			k = minInt(k, maxBatch)
		}
		if err := s.send(p[:k]); err != nil {
			s.l.close() // the lane cannot be written to any more; the read loop ends with it
			return total, err
		}
		total += k
		p = p[k:]
	}
	return total, nil
}

// send writes one batch. Caller holds wmu.
func (s *serverStream) send(b []byte) error {
	if s.raw {
		if len(b) >= rawMin {
			return s.l.writeRaw(b)
		}
		s.frames = appendData(s.frames[:0], b)
		return s.l.writeUnshaped(s.frames)
	}
	ready := s.scan.feed(b)
	s.pkt++
	s.frames = appendData(s.frames[:0], b)
	if err := s.l.writePacket(s.pkt, s.frames); err != nil {
		return err
	}
	// The record header that makes the direction ready went out as DATA; raw segments start with the
	// next batch, provided the client can take them.
	if ready && s.l.peerRaw.Load() {
		s.raw = true
	}
	return nil
}

// CloseWrite ends the downlink (a half-close). The uplink keeps going.
func (s *serverStream) CloseWrite() error {
	return s.endDownlink()
}

// Close ends the stream: the downlink is closed with END and what is left of the uplink is dropped.
// The lane stays usable.
func (s *serverStream) Close() error {
	s.stopRead(net.ErrClosed)
	return s.endDownlink()
}

// endDownlink sends END, once. It is not shaped: END has to be the last byte of the direction. A PAD
// after it would reach the client once the lane is back in its pool, where data on an idle lane means
// "the server is closing".
func (s *serverStream) endDownlink() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.downEnded {
		return nil
	}
	s.downEnded = true
	err := s.l.writeFrame(frEnd, nil)
	if err != nil {
		s.l.close()
	}
	// Record the end of the downlink (which may arm the lane's idle deadline) before announcing it:
	// the read loop clears that deadline for the next stream as soon as it sees done closed, and a
	// deadline set afterwards would land on that stream.
	s.finish(false, true)
	close(s.done)
	return err
}

// finish records the end of a direction. Once both have ended the lane starts counting idle time.
func (s *serverStream) finish(up, down bool) {
	s.mu.Lock()
	s.upDone = s.upDone || up
	s.downDone = s.downDone || down
	done := s.upDone && s.downDone
	s.mu.Unlock()
	if done {
		_ = s.l.conn.SetReadDeadline(time.Now().Add(s.idle))
	}
}

func (s *serverStream) LocalAddr() net.Addr  { return s.l.conn.LocalAddr() }
func (s *serverStream) RemoteAddr() net.Addr { return s.l.conn.RemoteAddr() }

func (s *serverStream) SetDeadline(t time.Time) error {
	_ = s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

func (s *serverStream) SetReadDeadline(t time.Time) error {
	s.rd.Set(t)
	return nil
}

// SetWriteDeadline makes a Write that starts after t fail. One that is already under way is not
// interrupted: giving up in the middle of a record would break the lane.
func (s *serverStream) SetWriteDeadline(t time.Time) error {
	s.wd.Set(t)
	return nil
}

var _ interface {
	net.Conn
	CloseWrite() error
} = (*serverStream)(nil)
