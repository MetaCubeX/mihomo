package xraymux

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type sessionOwner interface {
	// writeFrame consumes frame and its payload before returning.
	writeFrame(Frame) error
	removeSession(uint16)
}

type workerSession interface {
	deliverDecodedFrame(decodedFrame) error
	closeCarrier(error)
}

// logicalConn is the caller-facing half of a logical Mux stream. net.Pipe gives
// each direction independent buffering and deadline state while the session
// goroutines translate the other half to and from Xray Mux frames.
type logicalConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
	session    *session
}

func (c *logicalConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *logicalConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *logicalConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		if cause := c.session.terminalCause(); cause != nil {
			return n, cause
		}
	}
	return n, err
}

func (c *logicalConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		if cause := c.session.terminalCause(); cause != nil {
			return n, cause
		}
	}
	return n, err
}

type muxAddr string

func (a muxAddr) Network() string { return "xray-mux" }
func (a muxAddr) String() string  { return string(a) }

type session struct {
	owner       sessionOwner
	id          uint16
	destination string
	port        uint16
	peer        net.Conn
	client      net.Conn
	downlink    chan downlinkMessage
	done        chan struct{}
	closeOnce   sync.Once
	causeMu     sync.Mutex
	cause       error
}

type downlinkMessage struct {
	payload       []byte
	payloadPooled bool
	terminal      bool
	cause         error
}

func (m *downlinkMessage) releasePayload() {
	frame := decodedFrame{Frame: Frame{Payload: m.payload}, payloadPooled: m.payloadPooled}
	frame.releasePayload()
	m.payload = nil
	m.payloadPooled = false
}

var sessionBufferPool = sync.Pool{
	New: func() any { return new([MaxPayloadSize]byte) },
}

func newSession(
	ctx context.Context,
	owner sessionOwner,
	id uint16,
	destination string,
	port uint16,
	firstPayloadTimeout time.Duration,
) (net.Conn, *session) {
	logical, s := makeSession(owner, id, destination, port)
	s.start(ctx, firstPayloadTimeout)
	return logical, s
}

func makeSession(owner sessionOwner, id uint16, destination string, port uint16) (net.Conn, *session) {
	client, peer := net.Pipe()
	s := &session{
		owner:       owner,
		id:          id,
		destination: destination,
		port:        port,
		peer:        peer,
		client:      client,
		downlink:    make(chan downlinkMessage, 16),
		done:        make(chan struct{}),
	}
	logical := &logicalConn{
		Conn:       client,
		localAddr:  muxAddr("xray-mux"),
		remoteAddr: muxAddr(net.JoinHostPort(destination, strconv.Itoa(int(port)))),
		session:    s,
	}
	return logical, s
}

func (s *session) start(ctx context.Context, firstPayloadTimeout time.Duration) {
	go s.runUplink(firstPayloadTimeout)
	go s.runDownlink()
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

func (s *session) runUplink(firstPayloadTimeout time.Duration) {
	if firstPayloadTimeout > 0 {
		_ = s.peer.SetReadDeadline(time.Now().Add(firstPayloadTimeout))
	}

	sentNew := false
	pooledBuffer := sessionBufferPool.Get().(*[MaxPayloadSize]byte)
	defer sessionBufferPool.Put(pooledBuffer)
	buffer := pooledBuffer[:]
	for {
		n, err := s.peer.Read(buffer)
		if err != nil && !sentNew && isNetTimeout(err) {
			if writeErr := s.owner.writeFrame(Frame{
				SessionID:   s.id,
				Status:      StatusNew,
				Network:     NetworkTCP,
				Destination: s.destination,
				Port:        s.port,
			}); writeErr != nil {
				s.finish(writeErr, false)
				return
			}
			sentNew = true
			_ = s.peer.SetReadDeadline(time.Time{})
			continue
		}
		if n > 0 {
			frame := Frame{
				SessionID: s.id,
				Status:    StatusKeep,
				Option:    OptionData,
				Payload:   buffer[:n],
			}
			if !sentNew {
				frame.Status = StatusNew
				frame.Network = NetworkTCP
				frame.Destination = s.destination
				frame.Port = s.port
				sentNew = true
				_ = s.peer.SetReadDeadline(time.Time{})
			}
			if writeErr := s.owner.writeFrame(frame); writeErr != nil {
				s.finish(writeErr, false)
				return
			}
		}
		if err != nil {
			s.finish(nil, errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed))
			return
		}
	}
}

func (s *session) runDownlink() {
	for {
		select {
		case message := <-s.downlink:
			err := writeFull(s.peer, message.payload)
			message.releasePayload()
			if err != nil {
				s.finish(nil, true)
				return
			}
			if message.terminal {
				s.finish(message.cause, false)
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *session) deliver(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	// DecodeFrame allocates payload ownership for this session. Transfer that
	// buffer directly to the downlink queue instead of copying every frame.
	return s.enqueueDownlink(downlinkMessage{payload: payload})
}

func (s *session) deliverFinal(payload []byte, cause error) error {
	return s.enqueueDownlink(downlinkMessage{
		payload:  payload,
		terminal: true,
		cause:    cause,
	})
}

func (s *session) deliverFrame(frame Frame) error {
	return s.deliverDecodedFrame(decodedFrame{Frame: frame})
}

func (s *session) deliverDecodedFrame(decoded decodedFrame) error {
	frame := decoded.Frame
	terminal := frame.Status == StatusEnd || frame.Option&OptionError != 0
	message := downlinkMessage{payload: frame.Payload, payloadPooled: decoded.payloadPooled}
	if terminal {
		var cause error
		if frame.Option&OptionError != 0 {
			cause = protocolError("remote session", errors.New("remote reported an error"))
		}
		message.terminal = true
		message.cause = cause
		return s.enqueueDownlink(message)
	}
	if frame.Option&OptionData != 0 {
		return s.enqueueDownlink(message)
	}
	decoded.releasePayload()
	return nil
}

func (s *session) enqueueDownlink(message downlinkMessage) error {
	select {
	case s.downlink <- message:
		return nil
	case <-s.done:
		message.releasePayload()
		return net.ErrClosed
	}
}

func (s *session) closeCarrier(cause error) {
	s.finish(cause, false)
}

func (s *session) finish(cause error, sendEnd bool) {
	s.closeOnce.Do(func() {
		s.causeMu.Lock()
		s.cause = cause
		s.causeMu.Unlock()
		if sendEnd {
			_ = s.owner.writeFrame(Frame{SessionID: s.id, Status: StatusEnd})
		}
		close(s.done)
		_ = s.peer.Close()
		// A clean remote End is represented by closing the peer side only. That
		// lets the caller drain any final payload and then observe io.EOF instead
		// of racing with a local close and receiving io.ErrClosedPipe.
		if cause != nil || sendEnd {
			_ = s.client.Close()
		}
		s.owner.removeSession(s.id)
	})
}

func (s *session) terminalCause() error {
	s.causeMu.Lock()
	defer s.causeMu.Unlock()
	return s.cause
}

func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
