package session

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Stream implements net.Conn
type Stream struct {
	id uint32

	sess *Session

	pipeR *io.PipeReader
	pipeW *io.PipeWriter

	dieOnce sync.Once
	dieHook func()
}

// newStream initiates a Stream struct
func newStream(id uint32, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.pipeR, s.pipeW = io.Pipe()
	return s
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	return s.pipeR.Read(b)
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	f := newFrame(cmdPSH, s.id)
	f.data = b
	n, err = s.sess.writeFrame(f)
	return
}

// Close implements net.Conn
func (s *Stream) Close() error {
	if s.sessionClose() {
		// notify remote
		return s.sess.streamClosed(s.id)
	} else {
		return io.ErrClosedPipe
	}
}

// sessionClose close stream from session side, do not notify remote
func (s *Stream) sessionClose() (once bool) {
	s.dieOnce.Do(func() {
		s.pipeR.Close()
		once = true
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
	})
	return
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return os.ErrNotExist
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	return os.ErrNotExist
}

func (s *Stream) SetDeadline(t time.Time) error {
	return os.ErrNotExist
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}
