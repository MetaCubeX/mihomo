package openvpn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

type deadlinePanicConn struct {
	net.Conn
}

func (*deadlinePanicConn) SetDeadline(time.Time) error {
	panic("physical SetDeadline called")
}

func (*deadlinePanicConn) SetReadDeadline(time.Time) error {
	panic("physical SetReadDeadline called")
}

func (*deadlinePanicConn) SetWriteDeadline(time.Time) error {
	panic("physical SetWriteDeadline called")
}

func TestPhysicalPacketIODoesNotCallDeadlineMethods(t *testing.T) {
	t.Run("tcp logical read deadline", func(t *testing.T) {
		clientNet, serverNet := net.Pipe()
		defer serverNet.Close()
		mux := NewPacketMux(NewTCPPacketIO(&deadlinePanicConn{Conn: clientNet}))
		go mux.Run()
		defer mux.Close()

		var clientID SessionID
		copy(clientID[:], []byte("client01"))
		conn := NewControlConn(NewControlChannel(mux, nil, clientID))
		if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("logical deadline returned %v", err)
		}
		select {
		case <-mux.done:
			t.Fatalf("logical read deadline closed physical transport: %v", mux.terminalError())
		default:
		}
	})

	t.Run("tcp write", func(t *testing.T) {
		clientNet, serverNet := net.Pipe()
		defer clientNet.Close()
		defer serverNet.Close()
		packetIO := NewTCPPacketIO(&deadlinePanicConn{Conn: clientNet})
		payload := []byte("framed")
		readDone := make(chan error, 1)
		go func() {
			frame := make([]byte, len(payload)+2)
			_, err := io.ReadFull(serverNet, frame)
			if err == nil && !bytes.Equal(frame[2:], payload) {
				err = errors.New("unexpected TCP frame payload")
			}
			readDone <- err
		}()
		if err := packetIO.WritePacket(payload); err != nil {
			t.Fatal(err)
		}
		if err := <-readDone; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("udp write", func(t *testing.T) {
		clientNet, serverNet := net.Pipe()
		defer clientNet.Close()
		defer serverNet.Close()
		packetIO := NewDatagramPacketIO(&deadlinePanicConn{Conn: clientNet})
		payload := []byte("datagram")
		readDone := make(chan error, 1)
		go func() {
			buf := make([]byte, len(payload))
			_, err := io.ReadFull(serverNet, buf)
			if err == nil && !bytes.Equal(buf, payload) {
				err = errors.New("unexpected UDP payload")
			}
			readDone <- err
		}()
		if err := packetIO.WritePacket(payload); err != nil {
			t.Fatal(err)
		}
		if err := <-readDone; err != nil {
			t.Fatal(err)
		}
	})
}

type writeResultConn struct {
	n   int
	err error
}

func (*writeResultConn) Read([]byte) (int, error)    { return 0, net.ErrClosed }
func (c *writeResultConn) Write([]byte) (int, error) { return c.n, c.err }
func (*writeResultConn) Close() error                { return nil }
func (*writeResultConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (*writeResultConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }

type readResultConn struct {
	packet []byte
	err    error
}

func (c *readResultConn) Read(p []byte) (int, error) {
	return copy(p, c.packet), c.err
}
func (*readResultConn) Write(p []byte) (int, error) { return len(p), nil }
func (*readResultConn) Close() error                { return nil }
func (*readResultConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (*readResultConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }

type syscallWriteResultConn struct {
	*writeResultConn
}

func (*syscallWriteResultConn) SyscallConn() (syscall.RawConn, error) {
	return nil, nil
}

func TestDatagramPacketIOWriteClassification(t *testing.T) {
	packet := []byte("packet")
	dropCause := errors.New("single datagram rejected")
	tests := []struct {
		name        string
		conn        connIO
		want        error
		wantDropped bool
	}{
		{
			name:        "syscall UDP zero-byte nonterminal error is one packet loss",
			conn:        &syscallWriteResultConn{&writeResultConn{err: dropCause}},
			want:        dropCause,
			wantDropped: true,
		},
		{
			name: "non-syscall transport error is fatal",
			conn: &writeResultConn{err: dropCause},
			want: dropCause,
		},
		{
			name: "timeout is fatal",
			conn: &syscallWriteResultConn{&writeResultConn{err: os.ErrDeadlineExceeded}},
			want: os.ErrDeadlineExceeded,
		},
		{
			name: "closed is fatal",
			conn: &syscallWriteResultConn{&writeResultConn{err: net.ErrClosed}},
			want: net.ErrClosed,
		},
		{
			name: "partial datagram preserves physical error",
			conn: &syscallWriteResultConn{&writeResultConn{n: 1, err: dropCause}},
			want: dropCause,
		},
		{
			name: "complete write preserves accompanying error",
			conn: &syscallWriteResultConn{&writeResultConn{n: len(packet), err: dropCause}},
			want: dropCause,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewDatagramPacketIO(tc.conn).WritePacket(packet)
			if tc.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("WritePacket error = %v, want %v", err, tc.want)
			}
			if got := errors.Is(err, errPacketDropped); got != tc.wantDropped {
				t.Fatalf("packet-dropped classification = %t, want %t", got, tc.wantDropped)
			}
		})
	}
}

func TestPacketMuxDeliversDatagramReturnedWithReadError(t *testing.T) {
	readErr := io.EOF
	packet := []byte{opcodeKeyID(PDataV2, 0), 1, 2, 3}
	mux := NewPacketMux(NewDatagramPacketIO(&readResultConn{
		packet: packet,
		err:    readErr,
	}))
	go mux.Run()

	select {
	case <-mux.done:
	case <-time.After(time.Second):
		t.Fatal("physical reader did not report EOF")
	}

	got, err := mux.ReadDataPacket(context.Background())
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("packet returned with EOF = %x, %v; want %x", got, err, packet)
	}
	if _, err := mux.ReadDataPacket(context.Background()); !errors.Is(err, readErr) {
		t.Fatalf("terminal read error = %v, want %v", err, readErr)
	}
}

type physicalWriteCall struct {
	packet []byte
	result chan error
}

type controlledPacketIO struct {
	writes    chan *physicalWriteCall
	closed    chan struct{}
	closeOnce sync.Once
}

// cancelBeforePhysicalContext closes Done as the gate-level Err check returns,
// placing cancellation before the physical-write commit.
type cancelBeforePhysicalContext struct {
	done chan struct{}

	mu       sync.Mutex
	errCalls int
}

func (c *cancelBeforePhysicalContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelBeforePhysicalContext) Done() <-chan struct{}       { return c.done }
func (c *cancelBeforePhysicalContext) Value(any) any               { return nil }

func (c *cancelBeforePhysicalContext) Err() error {
	c.mu.Lock()
	c.errCalls++
	first := c.errCalls == 1
	c.mu.Unlock()
	if first {
		close(c.done)
		return nil
	}
	return context.Canceled
}

func newControlledPacketIO() *controlledPacketIO {
	return &controlledPacketIO{
		writes: make(chan *physicalWriteCall, 16),
		closed: make(chan struct{}),
	}
}

func (p *controlledPacketIO) ReadPacket() ([]byte, error) {
	<-p.closed
	return nil, net.ErrClosed
}

func (p *controlledPacketIO) WritePacket(packet []byte) error {
	call := &physicalWriteCall{packet: append([]byte(nil), packet...), result: make(chan error, 1)}
	select {
	case p.writes <- call:
	case <-p.closed:
		return net.ErrClosed
	}
	select {
	case err := <-call.result:
		return err
	case <-p.closed:
		return net.ErrClosed
	}
}

func (p *controlledPacketIO) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (*controlledPacketIO) LocalAddr() net.Addr  { return dummyAddr("local") }
func (*controlledPacketIO) RemoteAddr() net.Addr { return dummyAddr("remote") }

func waitWriteGateQueues(t *testing.T, mux *PacketMux, control, data int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		mux.gate.mu.Lock()
		gotControl, gotData := len(mux.gate.control), len(mux.gate.data)
		mux.gate.mu.Unlock()
		if gotControl == control && gotData == data {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("write queues = control %d data %d, want control %d data %d", gotControl, gotData, control, data)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPacketMuxActiveDataCancellationKeepsTransport(t *testing.T) {
	packetIO := newControlledPacketIO()
	mux := NewPacketMux(packetIO)
	defer mux.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- mux.WriteDataPacket(ctx, []byte("data")) }()
	call := <-packetIO.writes
	<-ctx.Done()
	select {
	case err := <-result:
		t.Fatalf("active data write returned before physical completion: %v", err)
	default:
	}
	select {
	case <-mux.done:
		t.Fatalf("data cancellation closed transport: %v", mux.terminalError())
	default:
	}
	call.result <- nil
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestPacketMuxCancellationBeforePhysicalCommitKeepsTransport(t *testing.T) {
	packetIO := &staticErrorPacketIO{closed: make(chan struct{})}
	mux := NewPacketMux(packetIO)
	defer mux.Close()
	ctx := &cancelBeforePhysicalContext{done: make(chan struct{})}
	if err := mux.WritePacket(ctx, []byte("control")); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-physical cancellation returned %v", err)
	}
	select {
	case <-mux.done:
		t.Fatalf("pre-physical cancellation closed transport: %v", mux.terminalError())
	default:
	}
}

func TestPacketMuxActiveControlCancellationClosesTransport(t *testing.T) {
	packetIO := newControlledPacketIO()
	mux := NewPacketMux(packetIO)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- mux.WritePacket(ctx, []byte("control")) }()
	<-packetIO.writes
	select {
	case <-mux.done:
		if !errors.Is(mux.terminalError(), context.DeadlineExceeded) {
			t.Fatalf("terminal error = %v", mux.terminalError())
		}
	case <-time.After(time.Second):
		t.Fatal("active control timeout did not close transport")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("active control write returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("physical control write was not interrupted by Close")
	}
}

func TestReliableRetransmitDeadlineAbortsActivePhysicalWrite(t *testing.T) {
	packetIO := newControlledPacketIO()
	mux := NewPacketMux(packetIO)
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	channel := NewControlChannel(mux, nil, clientID)

	initialResult := make(chan error, 1)
	go func() {
		_, err := channel.Send(context.Background(), PControlV1, []byte("pending"))
		initialResult <- err
	}()
	initial := <-packetIO.writes
	initial.result <- nil
	if err := <-initialResult; err != nil {
		t.Fatal(err)
	}

	retransmitResult := make(chan error, 1)
	go func() { retransmitResult <- channel.RetransmitPending(context.Background()) }()
	<-packetIO.writes
	if err := channel.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-mux.done:
		if !errors.Is(mux.terminalError(), context.DeadlineExceeded) {
			t.Fatalf("terminal error = %v", mux.terminalError())
		}
	case <-time.After(time.Second):
		t.Fatal("logical write deadline did not terminate active retransmit")
	}
	select {
	case err := <-retransmitResult:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("active retransmit returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("active retransmit was not interrupted")
	}
}

func TestPacketMuxQueuedCancellationKeepsTransport(t *testing.T) {
	packetIO := newControlledPacketIO()
	mux := NewPacketMux(packetIO)
	defer mux.Close()
	firstResult := make(chan error, 1)
	go func() { firstResult <- mux.WriteDataPacket(context.Background(), []byte("active")) }()
	first := <-packetIO.writes

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := mux.WritePacket(ctx, []byte("queued")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued control write returned %v", err)
	}
	mux.gate.mu.Lock()
	controlQueue := mux.gate.control
	mux.gate.mu.Unlock()
	if controlQueue != nil {
		t.Fatalf("canceled write gate retained control queue: %d", len(controlQueue))
	}
	select {
	case <-mux.done:
		t.Fatalf("queued cancellation closed transport: %v", mux.terminalError())
	default:
	}
	first.result <- nil
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	select {
	case call := <-packetIO.writes:
		t.Fatalf("canceled queued packet reached physical writer: %q", call.packet)
	default:
	}
}

func TestPacketMuxPrioritizesQueuedControl(t *testing.T) {
	packetIO := newControlledPacketIO()
	mux := NewPacketMux(packetIO)
	defer mux.Close()
	results := make(chan error, 3)
	go func() { results <- mux.WriteDataPacket(context.Background(), []byte("data-1")) }()
	first := <-packetIO.writes
	go func() { results <- mux.WriteDataPacket(context.Background(), []byte("data-2")) }()
	go func() { results <- mux.WritePacket(context.Background(), []byte("control")) }()
	waitWriteGateQueues(t, mux, 1, 1)
	first.result <- nil
	second := <-packetIO.writes
	if string(second.packet) != "control" {
		t.Fatalf("second physical write = %q, want control", second.packet)
	}
	second.result <- nil
	third := <-packetIO.writes
	if string(third.packet) != "data-2" {
		t.Fatalf("third physical write = %q, want data-2", third.packet)
	}
	third.result <- nil
	for i := 0; i < 3; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	mux.gate.mu.Lock()
	controlQueue, dataQueue := mux.gate.control, mux.gate.data
	mux.gate.mu.Unlock()
	if controlQueue != nil || dataQueue != nil {
		t.Fatalf("drained write gate retained waiter queues: control=%d data=%d", len(controlQueue), len(dataQueue))
	}
}

func TestPacketMuxPreservesFirstPhysicalErrorForQueuedWriters(t *testing.T) {
	packetIO := newControlledPacketIO()
	mux := NewPacketMux(packetIO)
	fatalErr := errors.New("physical write failed")
	firstResult := make(chan error, 1)
	secondResult := make(chan error, 1)
	go func() { firstResult <- mux.WriteDataPacket(context.Background(), []byte("first")) }()
	first := <-packetIO.writes
	go func() { secondResult <- mux.WriteDataPacket(context.Background(), []byte("second")) }()
	waitWriteGateQueues(t, mux, 0, 1)
	first.result <- fatalErr
	if err := <-firstResult; !errors.Is(err, fatalErr) {
		t.Fatalf("first write error = %v", err)
	}
	if err := <-secondResult; !errors.Is(err, fatalErr) {
		t.Fatalf("queued write error = %v", err)
	}
	if !errors.Is(mux.terminalError(), fatalErr) {
		t.Fatalf("terminal error = %v", mux.terminalError())
	}
}

type queuedReadPacketIO struct {
	packets chan []byte
	closed  chan struct{}
	once    sync.Once
}

type finiteReadPacketIO struct {
	packets [][]byte
	err     error
}

func (p *finiteReadPacketIO) ReadPacket() ([]byte, error) {
	if len(p.packets) == 0 {
		return nil, p.err
	}
	packet := p.packets[0]
	p.packets = p.packets[1:]
	return packet, nil
}

func (*finiteReadPacketIO) WritePacket([]byte) error { return nil }
func (*finiteReadPacketIO) Close() error             { return nil }
func (*finiteReadPacketIO) LocalAddr() net.Addr      { return dummyAddr("local") }
func (*finiteReadPacketIO) RemoteAddr() net.Addr     { return dummyAddr("remote") }

func TestPacketMuxDrainsCompletePacketsBeforePhysicalReadError(t *testing.T) {
	readErr := io.EOF
	controlPacket := []byte{opcodeKeyID(PAckV1, 0)}
	dataPacket := []byte{opcodeKeyID(PDataV2, 0), 1, 2, 3}
	mux := NewPacketMux(&finiteReadPacketIO{
		packets: [][]byte{controlPacket, dataPacket},
		err:     readErr,
	})
	go mux.Run()

	select {
	case <-mux.done:
	case <-time.After(time.Second):
		t.Fatal("physical reader did not report EOF")
	}

	gotControl, err := mux.ReadPacket(context.Background())
	if err != nil || !bytes.Equal(gotControl, controlPacket) {
		t.Fatalf("queued control packet = %x, %v; want %x", gotControl, err, controlPacket)
	}
	gotData, err := mux.ReadDataPacket(context.Background())
	if err != nil || !bytes.Equal(gotData, dataPacket) {
		t.Fatalf("queued data packet = %x, %v; want %x", gotData, err, dataPacket)
	}
	if _, err := mux.ReadPacket(context.Background()); !errors.Is(err, readErr) {
		t.Fatalf("control terminal error = %v, want %v", err, readErr)
	}
	if _, err := mux.ReadDataPacket(context.Background()); !errors.Is(err, readErr) {
		t.Fatalf("data terminal error = %v, want %v", err, readErr)
	}
}

func TestPacketMuxExplicitCloseDoesNotDrainQueuedPackets(t *testing.T) {
	mux := NewPacketMux(&finiteReadPacketIO{})
	mux.control <- []byte{opcodeKeyID(PAckV1, 0)}
	if err := mux.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := mux.ReadPacket(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close = %v, want net.ErrClosed", err)
	}
}

func (p *queuedReadPacketIO) ReadPacket() ([]byte, error) {
	select {
	case packet := <-p.packets:
		return packet, nil
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

func (*queuedReadPacketIO) WritePacket([]byte) error { return nil }
func (p *queuedReadPacketIO) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}
func (*queuedReadPacketIO) LocalAddr() net.Addr  { return dummyAddr("local") }
func (*queuedReadPacketIO) RemoteAddr() net.Addr { return dummyAddr("remote") }

func TestPacketMuxReceiveQueueAppliesBackpressureWithoutDropping(t *testing.T) {
	packetIO := &queuedReadPacketIO{packets: make(chan []byte, 300), closed: make(chan struct{})}
	for i := 0; i < 257; i++ {
		packetIO.packets <- []byte{opcodeKeyID(PDataV2, 0), byte(i >> 8), byte(i)}
	}
	packetIO.packets <- []byte{opcodeKeyID(PAckV1, 0)}
	mux := NewPacketMux(packetIO)
	go mux.Run()
	defer mux.Close()

	deadline := time.Now().Add(time.Second)
	for len(mux.data) != cap(mux.data) {
		if time.Now().After(deadline) {
			t.Fatalf("data queue length = %d, want %d", len(mux.data), cap(mux.data))
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, err := mux.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if int(first[1])<<8|int(first[2]) != 0 {
		t.Fatalf("first data sequence = %v", first[1:])
	}
	if _, err := mux.ReadPacket(ctx); err != nil {
		t.Fatalf("control packet did not progress after backpressure released: %v", err)
	}
	for want := 1; want < 257; want++ {
		packet, err := mux.ReadDataPacket(ctx)
		if err != nil {
			t.Fatalf("read data %d: %v", want, err)
		}
		if got := int(packet[1])<<8 | int(packet[2]); got != want {
			t.Fatalf("data sequence = %d, want %d", got, want)
		}
	}
}

type staticErrorPacketIO struct {
	err       error
	closed    chan struct{}
	closeOnce sync.Once
}

func (p *staticErrorPacketIO) ReadPacket() ([]byte, error) {
	<-p.closed
	return nil, net.ErrClosed
}
func (p *staticErrorPacketIO) WritePacket([]byte) error { return p.err }
func (p *staticErrorPacketIO) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}
func (*staticErrorPacketIO) LocalAddr() net.Addr  { return dummyAddr("local") }
func (*staticErrorPacketIO) RemoteAddr() net.Addr { return dummyAddr("remote") }

type classifiedInitialUnreachableError struct{}

func (classifiedInitialUnreachableError) Error() string {
	return "classified initial network unreachable"
}
func (classifiedInitialUnreachableError) Is(target error) bool {
	return target == errPacketDropped || target == syscall.ENETUNREACH
}

func TestPacketMuxTreatsRecoverableUDPWriteAsPacketLoss(t *testing.T) {
	cause := errors.New("datagram rejected")
	packetIO := &staticErrorPacketIO{
		err:    &packetDroppedError{cause: cause},
		closed: make(chan struct{}),
	}
	mux := NewPacketMux(packetIO)
	defer mux.Close()
	if err := mux.WriteDataPacket(context.Background(), []byte("data")); !errors.Is(err, errPacketDropped) {
		t.Fatalf("recoverable data-packet loss = %v, want packet-dropped classification", err)
	}
	if err := mux.WritePacket(context.Background(), []byte("control")); !errors.Is(err, errPacketDropped) {
		t.Fatalf("recoverable control-packet loss = %v, want packet-dropped classification", err)
	}
	select {
	case <-mux.done:
		t.Fatalf("recoverable UDP packet loss closed transport: %v", mux.terminalError())
	default:
	}
}

func TestPacketMuxInitialNetworkUnreachableTerminatesTransport(t *testing.T) {
	packetIO := &staticErrorPacketIO{
		err:    &packetDroppedError{cause: syscall.ENETUNREACH},
		closed: make(chan struct{}),
	}
	mux := NewPacketMux(packetIO)
	err := mux.WritePacket(context.Background(), []byte("initial control"))
	if !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("initial network-unreachable write returned %v", err)
	}
	if errors.Is(err, errPacketDropped) {
		t.Fatalf("terminal initial error retained packet-dropped classification: %v", err)
	}
	select {
	case <-mux.done:
		if !errors.Is(mux.terminalError(), syscall.ENETUNREACH) {
			t.Fatalf("terminal error = %v", mux.terminalError())
		}
	default:
		t.Fatal("initial network-unreachable write kept transport alive")
	}
}

func TestControlInitialNetworkUnreachableFailsSendReset(t *testing.T) {
	packetIO := &staticErrorPacketIO{
		err:    classifiedInitialUnreachableError{},
		closed: make(chan struct{}),
	}
	mux := NewPacketMux(packetIO)
	channel := NewControlChannel(mux, nil, SessionID{})
	err := channel.SendReset(context.Background())
	if !errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, errPacketDropped) {
		t.Fatalf("SendReset error = %v, want terminal network-unreachable", err)
	}
	if !errors.Is(mux.terminalError(), syscall.ENETUNREACH) {
		t.Fatalf("terminal error = %v, want network-unreachable", mux.terminalError())
	}
}

func TestPacketMuxEstablishedNetworkUnreachableIsPacketLoss(t *testing.T) {
	packetIO := &staticErrorPacketIO{
		err:    &packetDroppedError{cause: syscall.ENETUNREACH},
		closed: make(chan struct{}),
	}
	mux := NewPacketMux(packetIO)
	defer mux.Close()
	mux.markInitialPacketReceived()
	if err := mux.WritePacket(context.Background(), []byte("established control")); !errors.Is(err, errPacketDropped) {
		t.Fatalf("established network-unreachable write returned %v", err)
	}
	select {
	case <-mux.done:
		t.Fatalf("established network-unreachable write closed transport: %v", mux.terminalError())
	default:
	}
}

func TestControlChannelTreatsRecoverableUDPWriteAsPacketLoss(t *testing.T) {
	packetIO := &staticErrorPacketIO{
		err:    &packetDroppedError{cause: errors.New("datagram rejected")},
		closed: make(chan struct{}),
	}
	mux := NewPacketMux(packetIO)
	defer mux.Close()
	channel := NewControlChannel(mux, nil, SessionID{})
	if _, err := channel.Send(context.Background(), PControlV1, []byte("reliable")); err != nil {
		t.Fatalf("recoverable control-packet loss escaped reliable layer: %v", err)
	}
	if channel.PendingMessages() != 1 {
		t.Fatalf("pending reliable messages = %d, want 1", channel.PendingMessages())
	}
	select {
	case <-mux.done:
		t.Fatalf("recoverable control-packet loss closed transport: %v", mux.terminalError())
	default:
	}
}

func TestDroppedDataPacketDoesNotMarkSendActivity(t *testing.T) {
	packetIO := &staticErrorPacketIO{
		err:    &packetDroppedError{cause: errors.New("datagram rejected")},
		closed: make(chan struct{}),
	}
	client, err := NewClient(&ClientConfig{}, packetIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	keys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	data, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(data)
	client.lastSendNano.Store(1)
	if err := client.WriteIPPacket(context.Background(), []byte{0x45, 0, 0, 20}); err != nil {
		t.Fatal(err)
	}
	if got := client.lastSendNano.Load(); got != 1 {
		t.Fatalf("dropped data packet updated send activity to %d", got)
	}
}
