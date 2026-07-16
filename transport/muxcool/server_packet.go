package muxcool

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const serverPacketQueueSize = 32

type serverPacketMessage struct {
	payload       []byte
	payloadPooled bool
	destination   M.Socksaddr
}

func (m *serverPacketMessage) release() {
	frame := decodedFrame{Frame: Frame{Payload: m.payload}, payloadPooled: m.payloadPooled}
	frame.releasePayload()
	m.payload = nil
	m.payloadPooled = false
}

type serverPacketFlow struct {
	runtime     *ServerRuntime
	key         xudpFlowKey
	ctx         context.Context
	cancel      context.CancelCauseFunc
	handler     ServerHandler
	source      M.Socksaddr
	destination M.Socksaddr
	reusable    bool

	input         chan serverPacketMessage
	done          chan struct{}
	readDeadline  deadline.PipeDeadline
	writeDeadline deadline.PipeDeadline
	readOptions   N.ReadWaitOptions

	mu         sync.Mutex
	current    *serverPacketAttachment
	generation uint64
	idleTimer  ServerTimer
	closed     bool
	closeErr   error
}

func newServerPacketFlow(
	runtime *ServerRuntime,
	key xudpFlowKey,
	ctx context.Context,
	cancel context.CancelCauseFunc,
	handler ServerHandler,
	source M.Socksaddr,
	destination M.Socksaddr,
	reusable bool,
) *serverPacketFlow {
	return &serverPacketFlow{
		runtime:       runtime,
		key:           key,
		ctx:           ctx,
		cancel:        cancel,
		handler:       handler,
		source:        source,
		destination:   destination,
		reusable:      reusable,
		input:         make(chan serverPacketMessage, serverPacketQueueSize),
		done:          make(chan struct{}),
		readDeadline:  deadline.MakePipeDeadline(),
		writeDeadline: deadline.MakePipeDeadline(),
	}
}

func (f *serverPacketFlow) runHandler() {
	err := f.handler.NewPacketConnection(f.ctx, f, M.Metadata{Source: f.source, Destination: f.destination})
	f.closeWithError(err)
}

func (f *serverPacketFlow) attach(carrier *serverCarrier, id uint16) (*serverPacketAttachment, error) {
	f.mu.Lock()
	if f.closed {
		err := f.closeErr
		if err == nil {
			err = net.ErrClosed
		}
		f.mu.Unlock()
		return nil, err
	}
	if f.idleTimer != nil {
		f.idleTimer.Stop()
		f.idleTimer = nil
	}
	f.generation++
	attachment := &serverPacketAttachment{
		flow:       f,
		carrier:    carrier,
		id:         id,
		generation: f.generation,
	}
	previous := f.current
	f.current = attachment
	f.mu.Unlock()

	if previous != nil {
		previous.finish(nil, true)
	}
	return attachment, nil
}

func (f *serverPacketFlow) detach(attachment *serverPacketAttachment, cause error) {
	f.mu.Lock()
	if f.current != attachment {
		f.mu.Unlock()
		return
	}
	f.current = nil
	if f.closed {
		f.mu.Unlock()
		return
	}
	if !f.reusable {
		f.mu.Unlock()
		f.closeWithError(cause)
		return
	}
	timeout := f.runtime.options.XUDPIdleTimeout
	generation := f.generation
	f.idleTimer = f.runtime.options.AfterFunc(timeout, func() {
		f.expire(generation)
	})
	f.mu.Unlock()
}

func (f *serverPacketFlow) enqueue(attachment *serverPacketAttachment, frame decodedFrame) error {
	f.mu.Lock()
	current := f.current == attachment && attachment.generation == f.generation && !f.closed
	f.mu.Unlock()
	if !current {
		frame.releasePayload()
		return net.ErrClosed
	}
	destination := socksaddrFromFrame(frame.Frame)
	if !destination.IsValid() {
		destination = f.destination
	}
	message := serverPacketMessage{
		payload:       frame.Payload,
		payloadPooled: frame.payloadPooled,
		destination:   destination,
	}
	select {
	case f.input <- message:
		return nil
	case <-f.done:
		message.release()
		return f.terminalError()
	default:
		message.release()
		return ErrSessionQueueFull
	}
}

func (f *serverPacketFlow) nextMessage() (serverPacketMessage, error) {
	select {
	case message := <-f.input:
		return message, nil
	default:
	}
	select {
	case message := <-f.input:
		return message, nil
	case <-f.done:
		return serverPacketMessage{}, f.terminalError()
	case <-f.readDeadline.Wait():
		return serverPacketMessage{}, os.ErrDeadlineExceeded
	}
}

func (f *serverPacketFlow) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	message, err := f.nextMessage()
	if err != nil {
		return M.Socksaddr{}, err
	}
	defer message.release()
	if _, err := buffer.Write(message.payload); err != nil {
		return M.Socksaddr{}, err
	}
	return message.destination, nil
}

func (f *serverPacketFlow) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	f.readOptions = options
	return false
}

func (f *serverPacketFlow) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	message, err := f.nextMessage()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	defer message.release()
	buffer := f.readOptions.NewPacketBuffer()
	if _, err := buffer.Write(message.payload); err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	f.readOptions.PostReturn(buffer)
	return buffer, message.destination, nil
}

func (f *serverPacketFlow) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	select {
	case <-f.done:
		return f.terminalError()
	case <-f.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	default:
	}
	f.mu.Lock()
	attachment := f.current
	f.mu.Unlock()
	if attachment == nil {
		// A reusable XUDP backend may emit a late response while detached. The
		// packet belongs to no active carrier generation and must be dropped.
		return nil
	}
	err := attachment.writePacket(buffer.Bytes(), destination)
	if err == nil {
		return nil
	}
	// A write admitted by the old generation may finish after a rebind. Its
	// failure owns only that retired attachment and must not kill the current
	// XUDP backend or attachment.
	f.mu.Lock()
	current := f.current == attachment && f.generation == attachment.generation
	f.mu.Unlock()
	if !current {
		return nil
	}
	return err
}

func (f *serverPacketFlow) LocalAddr() net.Addr { return muxAddr("mux.cool-udp-server") }

func (f *serverPacketFlow) Close() error {
	f.closeWithError(nil)
	return nil
}

func (f *serverPacketFlow) SetDeadline(value time.Time) error {
	f.readDeadline.Set(value)
	f.writeDeadline.Set(value)
	return nil
}

func (f *serverPacketFlow) SetReadDeadline(value time.Time) error {
	f.readDeadline.Set(value)
	return nil
}

func (f *serverPacketFlow) SetWriteDeadline(value time.Time) error {
	f.writeDeadline.Set(value)
	return nil
}

func (f *serverPacketFlow) closeWithError(cause error) {
	current, cause, closed := f.markClosed(cause, 0, false)
	if !closed {
		return
	}
	f.finishClose(current, cause)
}

func (f *serverPacketFlow) expire(generation uint64) {
	current, cause, closed := f.markClosed(context.DeadlineExceeded, generation, true)
	if !closed {
		return
	}
	f.finishClose(current, cause)
}

func (f *serverPacketFlow) markClosed(cause error, generation uint64, requireIdleGeneration bool) (*serverPacketAttachment, error, bool) {
	if cause == nil {
		cause = net.ErrClosed
	}
	f.mu.Lock()
	if f.closed || (requireIdleGeneration && (f.current != nil || f.generation != generation)) {
		f.mu.Unlock()
		return nil, cause, false
	}
	f.closed = true
	f.closeErr = cause
	if f.idleTimer != nil {
		f.idleTimer.Stop()
		f.idleTimer = nil
	}
	current := f.current
	f.current = nil
	f.mu.Unlock()
	return current, cause, true
}

func (f *serverPacketFlow) finishClose(current *serverPacketAttachment, cause error) {
	f.cancel(cause)
	close(f.done)
	if current != nil {
		current.finish(cause, true)
	}
	f.releaseQueued()
	if f.runtime != nil {
		f.runtime.removeFlow(f.key, f)
	}
}

func (f *serverPacketFlow) terminalError() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeErr != nil {
		return f.closeErr
	}
	return net.ErrClosed
}

func (f *serverPacketFlow) releaseQueued() {
	for {
		select {
		case message := <-f.input:
			message.release()
		default:
			return
		}
	}
}

type serverPacketAttachment struct {
	flow       *serverPacketFlow
	carrier    *serverCarrier
	id         uint16
	generation uint64
	closeOnce  sync.Once
}

func (a *serverPacketAttachment) deliverDecodedFrame(frame decodedFrame) error {
	if frame.Option&OptionData == 0 || len(frame.Payload) == 0 {
		frame.releasePayload()
		return nil
	}
	return a.flow.enqueue(a, frame)
}

func (a *serverPacketAttachment) writePacket(payload []byte, destination M.Socksaddr) error {
	host, ip, port := frameTarget(destination)
	return a.carrier.writeFrame(Frame{
		SessionID:     a.id,
		Status:        StatusKeep,
		Option:        OptionData,
		Network:       NetworkUDP,
		Destination:   host,
		DestinationIP: ip,
		Port:          port,
		Payload:       payload,
	})
}

func (a *serverPacketAttachment) finish(cause error, sendEnd bool) {
	a.closeOnce.Do(func() {
		a.carrier.removeSession(a.id, a)
		a.flow.detach(a, cause)
		if sendEnd {
			option := Option(0)
			if cause != nil && !errors.Is(cause, net.ErrClosed) && !errors.Is(cause, context.Canceled) {
				option = OptionError
			}
			_ = a.carrier.writeFrame(Frame{SessionID: a.id, Status: StatusEnd, Option: option})
		}
	})
}

var (
	_ N.PacketConn       = (*serverPacketFlow)(nil)
	_ N.PacketReadWaiter = (*serverPacketFlow)(nil)
	_ serverSession      = (*serverPacketAttachment)(nil)
)
