package openvpn

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/metacubex/mihomo/common/contextutils"
)

type PacketMux struct {
	io PacketIO

	control               chan []byte
	data                  chan []byte
	done                  chan struct{}
	gate                  priorityWriteGate
	initialPacketReceived atomic.Bool

	closeOnce sync.Once
	errMu     sync.Mutex
	closeErr  error
	// drainReads is set only when the physical reader terminates. Packets it
	// queued before the terminal read error remain valid and are delivered first.
	drainReads bool
}

var errControlRetransmitStopped = errors.New("openvpn control retransmitter stopped")

type activeWriteCancelPolicy uint8

const (
	ignoreActiveWriteCancel activeWriteCancelPolicy = iota
	abortActiveWrite
	allowActiveRetransmitStop
)

func NewPacketMux(io PacketIO) *PacketMux {
	return &PacketMux{
		io:      io,
		control: make(chan []byte, 64),
		data:    make(chan []byte, 256),
		done:    make(chan struct{}),
	}
}

// Run is the sole physical reader. Logical read cancellation never reaches
// PacketIO; closing the mux is the only way to interrupt a blocked read.
func (m *PacketMux) Run() {
	for {
		packet, err := m.io.ReadPacket()
		if len(packet) > 0 {
			opcode, _ := parseOpcodeKeyID(packet[0])
			ch := m.data
			if opcode.IsControl() {
				ch = m.control
			}
			select {
			case ch <- packet:
			case <-m.done:
				return
			}
		}
		if err != nil {
			m.closeWithReadError(err)
			return
		}
	}
}

func (m *PacketMux) ReadPacket(ctx context.Context) ([]byte, error) {
	return m.read(ctx, m.control)
}

func (m *PacketMux) ReadDataPacket(ctx context.Context) ([]byte, error) {
	return m.read(ctx, m.data)
}

func (m *PacketMux) read(ctx context.Context, packets <-chan []byte) ([]byte, error) {
	select {
	case <-m.done:
		return m.readAfterClose(packets)
	default:
	}
	select {
	case packet := <-packets:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return m.readAfterClose(packets)
	}
}

func (m *PacketMux) readAfterClose(packets <-chan []byte) ([]byte, error) {
	if m.shouldDrainReads() {
		select {
		case packet := <-packets:
			return packet, nil
		default:
		}
	}
	return nil, m.terminalError()
}

// WritePacket is the ControlIO implementation used by ControlChannel.
func (m *PacketMux) WritePacket(ctx context.Context, packet []byte) error {
	return m.write(ctx, packet, true, abortActiveWrite)
}

// WritePacketAllowActiveStop is used by reliable retransmission. A normal
// retransmitter stop removes a queued write without aborting an active one;
// every other cancellation still terminates an active physical write.
func (m *PacketMux) WritePacketAllowActiveStop(ctx context.Context, packet []byte) error {
	return m.write(ctx, packet, true, allowActiveRetransmitStop)
}

func (m *PacketMux) WriteDataPacket(ctx context.Context, packet []byte) error {
	return m.write(ctx, packet, false, ignoreActiveWriteCancel)
}

func (m *PacketMux) markInitialPacketReceived() {
	m.initialPacketReceived.Store(true)
}

func (m *PacketMux) write(ctx context.Context, packet []byte, control bool, cancelPolicy activeWriteCancelPolicy) error {
	if err := m.currentError(); err != nil {
		return err
	}
	waiter, err := m.gate.acquire(ctx, m.done, control)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return m.terminalError()
		}
		return err
	}
	defer m.gate.release(waiter)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.currentError(); err != nil {
		return err
	}

	// Linearize cancellation with the point that commits the physical write.
	var activeMu sync.Mutex
	active := false
	stop := func() bool { return true }
	var abortDone chan struct{}
	trackActive := cancelPolicy != ignoreActiveWriteCancel && ctx.Done() != nil
	if trackActive {
		abortDone = make(chan struct{})
		stop = contextutils.AfterFunc(ctx, func() {
			defer close(abortDone)
			activeMu.Lock()
			isActive := active
			activeMu.Unlock()
			if isActive {
				err := context.Cause(ctx)
				if err == nil {
					err = ctx.Err()
				}
				if cancelPolicy == allowActiveRetransmitStop && errors.Is(err, errControlRetransmitStopped) {
					return
				}
				m.closeWithError(err)
			}
		})
		activeMu.Lock()
		if err := ctx.Err(); err != nil {
			activeMu.Unlock()
			if !stop() {
				<-abortDone
			}
			return err
		}
		active = true
		activeMu.Unlock()
	}

	err = m.io.WritePacket(packet)
	if trackActive {
		activeMu.Lock()
		active = false
		activeMu.Unlock()
	}
	if !stop() {
		<-abortDone
	}
	// Cancellation can close the transport concurrently with a physical write
	// that reports success. Once that close wins, never report the logical write
	// as successful to TLS or the control protocol.
	if terminalErr := m.currentError(); terminalErr != nil {
		return terminalErr
	}
	if errors.Is(err, errPacketDropped) {
		// OpenVPN immediately restarts when the initial UDP path is unreachable.
		// Once an initial reset has been accepted, the same socket
		// error is just loss of this datagram, like other UDP send failures.
		if !m.initialPacketReceived.Load() && errors.Is(err, syscall.ENETUNREACH) {
			terminalErr := error(syscall.ENETUNREACH)
			var dropped *packetDroppedError
			if errors.As(err, &dropped) && dropped.cause != nil {
				terminalErr = dropped.cause
			}
			if errors.Is(terminalErr, errPacketDropped) {
				terminalErr = syscall.ENETUNREACH
			}
			m.closeWithError(terminalErr)
			return terminalErr
		}
		return err
	}
	if err != nil {
		m.closeWithError(err)
	}
	return err
}

func (m *PacketMux) Close() error {
	m.closeWithError(net.ErrClosed)
	return nil
}

func (m *PacketMux) closeWithError(err error) {
	m.closeWithErrorMode(err, false)
}

func (m *PacketMux) closeWithReadError(err error) {
	m.closeWithErrorMode(err, true)
}

func (m *PacketMux) closeWithErrorMode(err error, drainReads bool) {
	if err == nil {
		err = net.ErrClosed
	}
	m.closeOnce.Do(func() {
		m.errMu.Lock()
		m.closeErr = err
		m.drainReads = drainReads
		m.errMu.Unlock()
		close(m.done)
		_ = m.io.Close()
	})
}

func (m *PacketMux) shouldDrainReads() bool {
	m.errMu.Lock()
	defer m.errMu.Unlock()
	return m.drainReads
}

func (m *PacketMux) currentError() error {
	select {
	case <-m.done:
		return m.terminalError()
	default:
		return nil
	}
}

func (m *PacketMux) terminalError() error {
	m.errMu.Lock()
	defer m.errMu.Unlock()
	if m.closeErr != nil {
		return m.closeErr
	}
	return net.ErrClosed
}

func (m *PacketMux) LocalAddr() net.Addr {
	return m.io.LocalAddr()
}

func (m *PacketMux) RemoteAddr() net.Addr {
	return m.io.RemoteAddr()
}

type writeWaiterState uint8

const (
	writeWaiterQueued writeWaiterState = iota
	writeWaiterGranted
	writeWaiterReleased
)

type writeWaiter struct {
	ready chan struct{}
	state writeWaiterState
}

type priorityWriteGate struct {
	mu      sync.Mutex
	active  bool
	control []*writeWaiter
	data    []*writeWaiter
}

func (g *priorityWriteGate) acquire(ctx context.Context, done <-chan struct{}, control bool) (*writeWaiter, error) {
	g.mu.Lock()
	if !g.active {
		g.active = true
		g.mu.Unlock()
		return nil, nil
	}
	w := &writeWaiter{ready: make(chan struct{}), state: writeWaiterQueued}
	if control {
		g.control = append(g.control, w)
	} else {
		g.data = append(g.data, w)
	}
	g.mu.Unlock()

	select {
	case <-w.ready:
		return w, nil
	case <-ctx.Done():
		g.abandon(w)
		return nil, ctx.Err()
	case <-done:
		g.abandon(w)
		return nil, net.ErrClosed
	}
}

func (g *priorityWriteGate) abandon(w *writeWaiter) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch w.state {
	case writeWaiterQueued:
		g.control = removeWriteWaiter(g.control, w)
		g.data = removeWriteWaiter(g.data, w)
		w.state = writeWaiterReleased
	case writeWaiterGranted:
		w.state = writeWaiterReleased
		g.grantNextLocked()
	}
}

func (g *priorityWriteGate) release(w *writeWaiter) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if w == nil {
		g.grantNextLocked()
		return
	}
	if w.state != writeWaiterGranted {
		return
	}
	w.state = writeWaiterReleased
	g.grantNextLocked()
}

func (g *priorityWriteGate) grantNextLocked() {
	var w *writeWaiter
	if len(g.control) > 0 {
		w = g.control[0]
		g.control[0] = nil
		g.control = g.control[1:]
		if len(g.control) == 0 {
			g.control = nil
		}
	} else if len(g.data) > 0 {
		w = g.data[0]
		g.data[0] = nil
		g.data = g.data[1:]
		if len(g.data) == 0 {
			g.data = nil
		}
	} else {
		g.active = false
		return
	}
	w.state = writeWaiterGranted
	close(w.ready)
}

func removeWriteWaiter(waiters []*writeWaiter, target *writeWaiter) []*writeWaiter {
	for i, waiter := range waiters {
		if waiter == target {
			copy(waiters[i:], waiters[i+1:])
			last := len(waiters) - 1
			waiters[last] = nil
			if last == 0 {
				return nil
			}
			return waiters[:last]
		}
	}
	return waiters
}
