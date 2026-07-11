package multiplex

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	frameOpen  byte = 0x01
	frameData  byte = 0x02
	frameClose byte = 0x03
	frameReset byte = 0x04
)

const (
	headerSize = 1 + 4 + 4
	// maxQueuedBytesPerStream bounds unread payload retained by a single logical stream.
	// A stream that exceeds the limit is reset so it cannot block the shared demux loop.
	maxQueuedBytesPerStream = 4 * 1024 * 1024
	maxFrameSize            = 256 * 1024
	maxDataPayload          = 128 * 1024
	keepaliveInterval       = 15 * time.Second
)

var errMuxReceiveQueueFull = errors.New("mux receive queue full")

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

	lastWrite     atomic.Int64
	keepaliveOnce sync.Once
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
	s.lastWrite.Store(time.Now().UnixNano())
	go s.readLoop()
	s.startKeepalive(keepaliveInterval)
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
	s.lastWrite.Store(time.Now().UnixNano())
	go s.readLoop()
	s.startKeepalive(keepaliveInterval)
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

func (s *Session) Done() <-chan struct{} {
	if s == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return s.closed
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

	if err := writeAllChunks(s.conn, header[:], payload); err != nil {
		s.closeWithError(err)
		return err
	}
	s.lastWrite.Store(time.Now().UnixNano())
	return nil
}

func (s *Session) startKeepalive(interval time.Duration) {
	if s == nil || interval <= 0 {
		return
	}
	s.keepaliveOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					lastWrite := time.Unix(0, s.lastWrite.Load())
					if time.Since(lastWrite) < interval {
						continue
					}
					// Stream zero is never allocated. v0.4.7 peers ignore DATA
					// frames for unknown streams, so this remains compatible.
					if err := s.sendFrame(frameData, 0, nil); err != nil {
						return
					}
				case <-s.closed:
					return
				}
			}
		}()
	})
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
			if err := st.enqueue(payload); err != nil {
				st.closeNoSend(err)
				s.removeStream(streamID)
				go s.sendReset(streamID, err.Error())
			}

		case frameClose:
			st := s.getStream(streamID)
			if st == nil {
				continue
			}
			if st.closeRemoteWrite() {
				s.removeStream(streamID)
			}

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

	writeMu sync.Mutex

	mu                sync.Mutex
	cond              *sync.Cond
	closed            bool
	localReadClosed   bool
	localWriteClosed  bool
	remoteWriteClosed bool
	closeErr          error
	readBuf           []byte
	queue             [][]byte
	// queuedBytes includes unread bytes in readBuf and queue.
	queuedBytes int

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

func (c *stream) closeRemoteWrite() bool {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false
	}
	c.remoteWriteClosed = true
	remove := c.localWriteClosed
	c.cond.Broadcast()
	c.mu.Unlock()
	return remove
}

func (c *stream) closedErr() error {
	c.mu.Lock()
	err := c.closedErrLocked()
	c.mu.Unlock()
	return err
}

func (c *stream) closedErrLocked() error {
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

	for len(c.readBuf) == 0 && len(c.queue) == 0 && !c.closed && !c.localReadClosed && !c.remoteWriteClosed {
		c.cond.Wait()
	}
	if len(c.readBuf) == 0 && len(c.queue) > 0 {
		c.readBuf = c.queue[0]
		c.queue[0] = nil
		c.queue = c.queue[1:]
		if len(c.queue) == 0 {
			c.queue = nil
		}
	}
	if len(c.readBuf) == 0 {
		switch {
		case c.closed:
			return 0, c.closedErrLocked()
		case c.localReadClosed:
			return 0, io.ErrClosedPipe
		case c.remoteWriteClosed:
			return 0, io.EOF
		}
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	if len(c.readBuf) == 0 {
		c.readBuf = nil
	}
	c.queuedBytes -= n
	if c.queuedBytes < 0 {
		c.queuedBytes = 0
	}
	c.cond.Broadcast()
	return n, nil
}

func (c *stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.session == nil {
		return 0, io.ErrClosedPipe
	}
	if c.session.IsClosed() {
		return 0, c.session.closedErr()
	}

	c.mu.Lock()
	closed := c.closed
	writeClosed := c.localWriteClosed
	c.mu.Unlock()
	if closed {
		return 0, c.closedErr()
	}
	if writeClosed {
		return 0, io.ErrClosedPipe
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
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	sendClose := !c.localWriteClosed
	c.closed = true
	c.localReadClosed = true
	c.localWriteClosed = true
	if c.closeErr == nil {
		c.closeErr = io.ErrClosedPipe
	}
	c.readBuf = nil
	c.queue = nil
	c.queuedBytes = 0
	c.cond.Broadcast()
	c.mu.Unlock()

	if c.session != nil {
		if sendClose {
			_ = c.session.sendFrame(frameClose, c.id, nil)
		}
		c.session.removeStream(c.id)
	}
	return nil
}

func (c *stream) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	if c.closed || c.localWriteClosed {
		c.mu.Unlock()
		return nil
	}
	c.localWriteClosed = true
	remove := c.remoteWriteClosed || c.localReadClosed
	c.mu.Unlock()

	if c.session == nil {
		return nil
	}
	err := c.session.sendFrame(frameClose, c.id, nil)
	if remove {
		c.session.removeStream(c.id)
	}
	return err
}

func (c *stream) CloseRead() error {
	c.mu.Lock()
	if c.closed || c.localReadClosed {
		c.mu.Unlock()
		return nil
	}
	c.localReadClosed = true
	c.readBuf = nil
	c.queue = nil
	c.queuedBytes = 0
	remove := c.localWriteClosed
	c.cond.Broadcast()
	c.mu.Unlock()

	if remove && c.session != nil {
		c.session.removeStream(c.id)
	}
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

func (c *stream) enqueue(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.localReadClosed || c.remoteWriteClosed {
		return nil
	}
	if c.queuedBytes+len(payload) > maxQueuedBytesPerStream {
		return errMuxReceiveQueueFull
	}
	c.queuedBytes += len(payload)
	if len(c.readBuf) == 0 && len(c.queue) == 0 {
		c.readBuf = payload
	} else {
		c.queue = append(c.queue, payload)
	}
	c.cond.Broadcast()
	return nil
}
