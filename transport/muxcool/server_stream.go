package muxcool

import (
	"errors"
	"io"
	"net"
	"sync"

	M "github.com/metacubex/sing/common/metadata"
)

const serverStreamQueueSize = 16

type serverStreamMessage struct {
	payload       []byte
	payloadPooled bool
}

func (m *serverStreamMessage) release() {
	frame := decodedFrame{Frame: Frame{Payload: m.payload}, payloadPooled: m.payloadPooled}
	frame.releasePayload()
	m.payload = nil
	m.payloadPooled = false
}

type serverStream struct {
	carrier     *serverCarrier
	id          uint16
	destination M.Socksaddr
	client      net.Conn
	peer        net.Conn
	input       chan serverStreamMessage
	done        chan struct{}
	closeOnce   sync.Once
}

func newServerStream(carrier *serverCarrier, id uint16, destination M.Socksaddr) *serverStream {
	client, peer := net.Pipe()
	return &serverStream{
		carrier:     carrier,
		id:          id,
		destination: destination,
		client:      client,
		peer:        peer,
		input:       make(chan serverStreamMessage, serverStreamQueueSize),
		done:        make(chan struct{}),
	}
}

func (s *serverStream) start() {
	go s.writeInput()
	go s.readOutput()
	go func() {
		metadata := M.Metadata{Source: s.carrier.metadata.Source, Destination: s.destination}
		if err := s.carrier.handler.NewConnection(s.carrier.ctx, s.client, metadata); err != nil {
			s.finish(err, true)
		}
	}()
}

func (s *serverStream) deliverDecodedFrame(frame decodedFrame) error {
	if frame.Option&OptionData == 0 || len(frame.Payload) == 0 {
		frame.releasePayload()
		return nil
	}
	message := serverStreamMessage{payload: frame.Payload, payloadPooled: frame.payloadPooled}
	select {
	case s.input <- message:
		return nil
	case <-s.done:
		message.release()
		return net.ErrClosed
	default:
		message.release()
		return ErrSessionQueueFull
	}
}

func (s *serverStream) writeInput() {
	for {
		select {
		case message := <-s.input:
			err := writeFull(s.peer, message.payload)
			message.release()
			if err != nil {
				s.finish(err, true)
				return
			}
		case <-s.done:
			s.releaseQueued()
			return
		}
	}
}

func (s *serverStream) readOutput() {
	buffer := sessionBufferPool.Get().(*[MaxPayloadSize]byte)
	defer sessionBufferPool.Put(buffer)
	for {
		n, err := s.peer.Read(buffer[:])
		if n > 0 {
			writeErr := s.carrier.writeFrame(Frame{
				SessionID: s.id,
				Status:    StatusKeep,
				Option:    OptionData,
				Payload:   buffer[:n],
			})
			if writeErr != nil {
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

func (s *serverStream) finish(cause error, sendEnd bool) {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.peer.Close()
		_ = s.client.Close()
		s.carrier.removeSession(s.id, s)
		if sendEnd {
			option := Option(0)
			if cause != nil && !errors.Is(cause, io.EOF) && !errors.Is(cause, net.ErrClosed) {
				option = OptionError
			}
			_ = s.carrier.writeFrame(Frame{SessionID: s.id, Status: StatusEnd, Option: option})
		}
	})
}

func (s *serverStream) releaseQueued() {
	for {
		select {
		case message := <-s.input:
			message.release()
		default:
			return
		}
	}
}

var _ serverSession = (*serverStream)(nil)
