package multiplex

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	frameOpen  byte = 0x01
	frameData  byte = 0x02
	frameClose byte = 0x03
	frameReset byte = 0x04
)

const (
	headerSize     = 1 + 4 + 4
	maxFrameSize   = 256 * 1024
	maxDataPayload = 32 * 1024
)

type acceptEvent struct {
	stream  *stream
	payload []byte
}

type Session struct {
	conn net.Conn

	writeMu sync.Mutex

	streamsMu sync.Mutex
	streams   map[uint32]*stream
	nextID    uint32

	acceptCh chan acceptEvent

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func NewClientSession(conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	s := &Session{
		conn:    conn,
		streams: make(map[uint32]*stream),
		closed:  make(chan struct{}),
	}
	go s.readLoop()
	return s, nil
}

func NewServerSession(conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	s := &Session{
		conn:     conn,
		streams:  make(map[uint32]*stream),
		acceptCh: make(chan acceptEvent, 256),
		closed:   make(chan struct{}),
	}
	go s.readLoop()
	return s, nil
}

func (s *Session) IsClosed() bool {
	if s == nil {
		return true
	}
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *Session) closedErr() error {
	s.streamsMu.Lock()
	err := s.closeErr
	s.streamsMu.Unlock()
	if err == nil {
		return io.ErrClosedPipe
	}
	return err
}

func (s *Session) closeWithError(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	s.closeOnce.Do(func() {
		s.streamsMu.Lock()
		if s.closeErr == nil {
			s.closeErr = err
		}
		streams := make([]*stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.streams = make(map[uint32]*stream)
		s.streamsMu.Unlock()

		for _, st := range streams {
			st.closeNoSend(err)
		}

		close(s.closed)
		_ = s.conn.Close()
	})
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.closeWithError(io.ErrClosedPipe)
	return nil
}

func (s *Session) registerStream(st *stream) {
	s.streamsMu.Lock()
	s.streams[st.id] = st
	s.streamsMu.Unlock()
}

func (s *Session) getStream(id uint32) *stream {
	s.streamsMu.Lock()
	st := s.streams[id]
	s.streamsMu.Unlock()
	return st
}

func (s *Session) removeStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

func (s *Session) nextStreamID() uint32 {
	s.streamsMu.Lock()
	s.nextID++
	id := s.nextID
	if id == 0 {
		s.nextID++
		id = s.nextID
	}
	s.streamsMu.Unlock()
	return id
}

func (s *Session) sendFrame(frameType byte, streamID uint32, payload []byte) error {
	if s.IsClosed() {
		return s.closedErr()
	}
	if len(payload) > maxFrameSize {
		return fmt.Errorf("mux payload too large: %d", len(payload))
	}

	var header [headerSize]byte
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:5], streamID)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := writeFull(s.conn, header[:]); err != nil {
		s.closeWithError(err)
		return err
	}
	if len(payload) > 0 {
		if err := writeFull(s.conn, payload); err != nil {
			s.closeWithError(err)
			return err
		}
	}
	return nil
}

func (s *Session) sendReset(streamID uint32, msg string) {
	if msg == "" {
		msg = "reset"
	}
	_ = s.sendFrame(frameReset, streamID, []byte(msg))
	_ = s.sendFrame(frameClose, streamID, nil)
}

func (s *Session) OpenStream(openPayload []byte) (net.Conn, error) {
	if s == nil {
		return nil, fmt.Errorf("nil session")
	}
	if s.IsClosed() {
		return nil, s.closedErr()
	}

	streamID := s.nextStreamID()
	st := newStream(s, streamID)
	s.registerStream(st)

	if err := s.sendFrame(frameOpen, streamID, openPayload); err != nil {
		st.closeNoSend(err)
		s.removeStream(streamID)
		return nil, fmt.Errorf("mux open failed: %w", err)
	}
	return st, nil
}

func (s *Session) AcceptStream() (net.Conn, []byte, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("nil session")
	}
	if s.acceptCh == nil {
		return nil, nil, fmt.Errorf("accept is not supported on client sessions")
	}
	select {
	case ev := <-s.acceptCh:
		return ev.stream, ev.payload, nil
	case <-s.closed:
		return nil, nil, s.closedErr()
	}
}

func (s *Session) readLoop() {
	var header [headerSize]byte
	for {
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			s.closeWithError(err)
			return
		}
		frameType := header[0]
		streamID := binary.BigEndian.Uint32(header[1:5])
		n := int(binary.BigEndian.Uint32(header[5:9]))
		if n < 0 || n > maxFrameSize {
			s.closeWithError(fmt.Errorf("invalid mux frame length: %d", n))
			return
		}

		var payload []byte
		if n > 0 {
			payload = make([]byte, n)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				s.closeWithError(err)
				return
			}
		}

		switch frameType {
		case frameOpen:
			if s.acceptCh == nil {
				s.sendReset(streamID, "unexpected open")
				continue
			}
			if streamID == 0 {
				s.sendReset(streamID, "invalid stream id")
				continue
			}
			if existing := s.getStream(streamID); existing != nil {
				s.sendReset(streamID, "stream already exists")
				continue
			}
			st := newStream(s, streamID)
			s.registerStream(st)
			go func() {
				select {
				case s.acceptCh <- acceptEvent{stream: st, payload: payload}:
				case <-s.closed:
					st.closeNoSend(io.ErrClosedPipe)
					s.removeStream(streamID)
				}
			}()

		case frameData:
			st := s.getStream(streamID)
			if st == nil {
				continue
			}
			if len(payload) == 0 {
				continue
			}
			st.enqueue(payload)

		case frameClose:
			st := s.getStream(streamID)
			if st == nil {
				continue
			}
			st.closeNoSend(io.EOF)
			s.removeStream(streamID)

		case frameReset:
			st := s.getStream(streamID)
			if st == nil {
				continue
			}
			msg := trimASCII(payload)
			if msg == "" {
				msg = "reset"
			}
			st.closeNoSend(errors.New(msg))
			s.removeStream(streamID)

		default:
			s.closeWithError(fmt.Errorf("unknown mux frame type: %d", frameType))
			return
		}
	}
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func trimASCII(b []byte) string {
	i := 0
	j := len(b)
	for i < j {
		c := b[i]
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			break
		}
		i++
	}
	for j > i {
		c := b[j-1]
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			break
		}
		j--
	}
	if i >= j {
		return ""
	}
	out := make([]byte, j-i)
	copy(out, b[i:j])
	return string(out)
}

type stream struct {
	session *Session
	id      uint32

	mu       sync.Mutex
	cond     *sync.Cond
	closed   bool
	closeErr error
	readBuf  []byte
	queue    [][]byte

	localAddr  net.Addr
	remoteAddr net.Addr
}

func newStream(session *Session, id uint32) *stream {
	st := &stream{
		session:    session,
		id:         id,
		localAddr:  &net.TCPAddr{},
		remoteAddr: &net.TCPAddr{},
	}
	st.cond = sync.NewCond(&st.mu)
	return st
}

func (c *stream) enqueue(payload []byte) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.queue = append(c.queue, payload)
	c.cond.Signal()
	c.mu.Unlock()
}

func (c *stream) closeNoSend(err error) {
	if err == nil {
		err = io.EOF
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	if c.closeErr == nil {
		c.closeErr = err
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *stream) closedErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeErr == nil {
		return io.ErrClosedPipe
	}
	return c.closeErr
}

func (c *stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(c.readBuf) == 0 && len(c.queue) == 0 && !c.closed {
		c.cond.Wait()
	}
	if len(c.readBuf) == 0 && len(c.queue) > 0 {
		c.readBuf = c.queue[0]
		c.queue = c.queue[1:]
	}
	if len(c.readBuf) == 0 && c.closed {
		if c.closeErr == nil {
			return 0, io.ErrClosedPipe
		}
		return 0, c.closeErr
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.session == nil || c.session.IsClosed() {
		if c.session != nil {
			return 0, c.session.closedErr()
		}
		return 0, io.ErrClosedPipe
	}

	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, c.closedErr()
	}

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxDataPayload {
			chunk = p[:maxDataPayload]
		}
		if err := c.session.sendFrame(frameData, c.id, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *stream) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.closeErr == nil {
		c.closeErr = io.ErrClosedPipe
	}
	c.cond.Broadcast()
	c.mu.Unlock()

	_ = c.session.sendFrame(frameClose, c.id, nil)
	c.session.removeStream(c.id)
	return nil
}

func (c *stream) LocalAddr() net.Addr  { return c.localAddr }
func (c *stream) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *stream) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}
func (c *stream) SetReadDeadline(time.Time) error  { return nil }
func (c *stream) SetWriteDeadline(time.Time) error { return nil }

