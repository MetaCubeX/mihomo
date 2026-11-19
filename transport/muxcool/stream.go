package muxcool

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// stream is one sub connection.
type stream struct {
	session *session
	id      uint16

	access   sync.Mutex
	cond     *sync.Cond
	queue    [][]byte
	buffered int
	readErr  error // set once no more data will be pushed
	closed   bool  // closed locally

	readDeadline  time.Time
	readTimer     *time.Timer
	writeDeadline time.Time
}

func newStream(s *session, id uint16) *stream {
	st := &stream{session: s, id: id}
	st.cond = sync.NewCond(&st.access)
	return st
}

// push is called by the session's read loop, it blocks while the reader is too slow.
func (st *stream) push(data []byte) {
	st.access.Lock()
	for st.buffered >= streamBufferLimit && st.readErr == nil && !st.closed {
		st.cond.Wait()
	}
	if st.readErr == nil && !st.closed {
		st.queue = append(st.queue, data)
		st.buffered += len(data)
		st.cond.Broadcast()
	}
	st.access.Unlock()
}

func (st *stream) closeWithError(err error) {
	st.access.Lock()
	if st.readErr == nil {
		st.readErr = err
	}
	st.cond.Broadcast()
	st.access.Unlock()
}

func (st *stream) Read(p []byte) (n int, err error) {
	st.access.Lock()
	defer st.access.Unlock()
	for {
		if st.closed {
			return 0, net.ErrClosed
		}
		if len(st.queue) > 0 {
			break
		}
		if st.readErr != nil {
			return 0, st.readErr
		}
		if !st.readDeadline.IsZero() && !time.Now().Before(st.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		st.cond.Wait()
	}
	if len(p) == 0 {
		return 0, nil
	}
	for n < len(p) && len(st.queue) > 0 {
		c := copy(p[n:], st.queue[0])
		n += c
		if c == len(st.queue[0]) {
			st.queue[0] = nil
			st.queue = st.queue[1:]
		} else {
			st.queue[0] = st.queue[0][c:]
		}
	}
	st.buffered -= n
	st.cond.Broadcast()
	return n, nil
}

func (st *stream) Write(p []byte) (n int, err error) {
	st.access.Lock()
	closed, readErr, deadline := st.closed, st.readErr, st.writeDeadline
	st.access.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if readErr != nil { // Mux.Cool can't half close, the remote end is gone
		if readErr == io.EOF {
			readErr = io.ErrClosedPipe
		}
		return 0, readErr
	}
	return st.session.writeData(st.id, p)
}

func (st *stream) Close() error {
	st.access.Lock()
	if st.closed {
		st.access.Unlock()
		return nil
	}
	st.closed = true
	st.queue = nil
	st.buffered = 0
	if st.readTimer != nil {
		st.readTimer.Stop()
		st.readTimer = nil
	}
	st.cond.Broadcast()
	st.access.Unlock()

	// only tell the remote peer when it doesn't know yet
	if st.session.remove(st.id) {
		st.session.writeEnd(st.id, false)
	}
	return nil
}

func (st *stream) LocalAddr() net.Addr  { return st.session.conn.LocalAddr() }
func (st *stream) RemoteAddr() net.Addr { return st.session.conn.RemoteAddr() }

func (st *stream) SetDeadline(t time.Time) error {
	_ = st.SetReadDeadline(t)
	return st.SetWriteDeadline(t)
}

func (st *stream) SetReadDeadline(t time.Time) error {
	st.access.Lock()
	defer st.access.Unlock()
	st.readDeadline = t
	if st.readTimer != nil {
		st.readTimer.Stop()
		st.readTimer = nil
	}
	if !t.IsZero() && !st.closed {
		// wake up the blocked readers when the deadline is reached
		st.readTimer = time.AfterFunc(time.Until(t), func() {
			st.access.Lock()
			st.cond.Broadcast()
			st.access.Unlock()
		})
	}
	st.cond.Broadcast()
	return nil
}

// SetWriteDeadline only prevents writes from starting after the deadline, a
// write blocked on the shared connection can't be interrupted.
func (st *stream) SetWriteDeadline(t time.Time) error {
	st.access.Lock()
	st.writeDeadline = t
	st.access.Unlock()
	return nil
}
