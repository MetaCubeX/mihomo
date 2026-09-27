package muxcool

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeCarrierDialer struct {
	mu       sync.Mutex
	calls    int
	carriers []*testCarrier
	errors   []error
}

type blockingCarrierDialer struct {
	mu          sync.Mutex
	started     chan struct{}
	startedOnce sync.Once
	release     chan struct{}
	carrier     *testCarrier
	calls       int
}

func newBlockingCarrierDialer() *blockingCarrierDialer {
	return &blockingCarrierDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
		carrier: newTestCarrier(),
	}
}

func (d *blockingCarrierDialer) dial(context.Context) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	d.startedOnce.Do(func() { close(d.started) })
	<-d.release
	return d.carrier, nil
}

func (d *blockingCarrierDialer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func (d *fakeCarrierDialer) dial(context.Context) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if len(d.errors) > 0 {
		err := d.errors[0]
		d.errors = d.errors[1:]
		if err != nil {
			return nil, err
		}
	}
	carrier := newTestCarrier()
	d.carriers = append(d.carriers, carrier)
	return carrier, nil
}

func (d *fakeCarrierDialer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func testPoolOptions() Options {
	return Options{
		MaxConcurrency:      8,
		MaxConnections:      128,
		FirstPayloadTimeout: time.Hour,
		IdleTimeout:         time.Hour,
	}
}

func TestPoolReusesCarrierAndExpandsAtActiveLimit(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	options := testPoolOptions()
	options.MaxConcurrency = 2
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = pool.Close() })

	first, err := pool.DialContext(context.Background(), "one.example", 80)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.DialContext(context.Background(), "two.example", 80)
	if err != nil {
		t.Fatal(err)
	}
	third, err := pool.DialContext(context.Background(), "three.example", 80)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	defer second.Close()
	defer third.Close()
	if got := dialer.callCount(); got != 2 {
		t.Fatalf("carrier dials = %d, want 2", got)
	}
}

func TestPoolMaxCarriersWaitsForReusableCarrier(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	options := testPoolOptions()
	options.MaxConcurrency = 1
	options.CarrierLimiter = NewCarrierLimiter(1)
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = pool.Close() })

	first, err := pool.DialContext(context.Background(), "one.example", 80)
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan net.Conn, 1)
	errors := make(chan error, 1)
	go func() {
		conn, err := pool.DialContext(context.Background(), "two.example", 80)
		if err != nil {
			errors <- err
			return
		}
		result <- conn
	}()

	select {
	case conn := <-result:
		_ = conn.Close()
		t.Fatal("second session opened while the only carrier was full")
	case err := <-errors:
		t.Fatalf("second session failed while waiting: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if got := dialer.callCount(); got != 1 {
		t.Fatalf("carrier dials while capped = %d, want 1", got)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case second := <-result:
		defer second.Close()
	case err := <-errors:
		t.Fatalf("second session after capacity release: %v", err)
	case <-time.After(time.Second):
		t.Fatal("second session did not reuse the carrier after capacity was released")
	}
	if got := dialer.callCount(); got != 1 {
		t.Fatalf("carrier dials after reuse = %d, want 1", got)
	}
}

func TestPoolMaxCarriersWaitHonorsContext(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	options := testPoolOptions()
	options.MaxConcurrency = 1
	options.CarrierLimiter = NewCarrierLimiter(1)
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = pool.Close() })

	first, err := pool.DialContext(context.Background(), "one.example", 80)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	cause := errors.New("carrier wait canceled")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	conn, err := pool.DialContext(ctx, "two.example", 80)
	if conn != nil || !errors.Is(err, cause) {
		t.Fatalf("canceled DialContext = (%v, %v), want (nil, %v)", conn, err, cause)
	}
	if got := dialer.callCount(); got != 1 {
		t.Fatalf("carrier dials after canceled wait = %d, want 1", got)
	}
}

func TestCarrierLimiterIsSharedAcrossPools(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	limiter := NewCarrierLimiter(1)
	options := testPoolOptions()
	options.MaxConcurrency = 1
	options.CarrierLimiter = limiter
	firstPool := NewPool(dialer.dial, options)
	secondPool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = firstPool.Close(); _ = secondPool.Close() })

	first, err := firstPool.DialContext(context.Background(), "one.example", 80)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if conn, err := secondPool.DialContext(ctx, "two.example", 80); conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second pool DialContext = (%v, %v), want deadline exceeded", conn, err)
	}
	if got := dialer.callCount(); got != 1 {
		t.Fatalf("shared carrier dials = %d, want 1", got)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := firstPool.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := secondPool.DialContext(context.Background(), "two.example", 80)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := dialer.callCount(); got != 2 {
		t.Fatalf("carrier dials after release = %d, want 2", got)
	}
}

func TestCarrierLimiterReleasesFailedDialReservation(t *testing.T) {
	dialErr := errors.New("dial failed")
	dialer := &fakeCarrierDialer{errors: []error{dialErr}}
	options := testPoolOptions()
	options.CarrierLimiter = NewCarrierLimiter(1)
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = pool.Close() })

	if _, err := pool.DialContext(context.Background(), "failure.example", 80); !errors.Is(err, dialErr) {
		t.Fatalf("first dial error = %v", err)
	}
	conn, err := pool.DialContext(context.Background(), "success.example", 80)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer conn.Close()
	if got := dialer.callCount(); got != 2 {
		t.Fatalf("carrier dials = %d, want 2", got)
	}
}

func TestPoolMaxCarriersIsStrictUnderConcurrency(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	options := testPoolOptions()
	options.MaxConcurrency = 1
	options.CarrierLimiter = NewCarrierLimiter(2)
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = pool.Close() })

	const callers = 16
	results := make(chan net.Conn, callers)
	errors := make(chan error, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		go func() {
			<-start
			conn, err := pool.DialContext(context.Background(), "shared.example", 443)
			if err != nil {
				errors <- err
				return
			}
			results <- conn
		}()
	}
	close(start)

	opened := make([]net.Conn, 0, 2)
	for len(opened) < 2 {
		select {
		case conn := <-results:
			opened = append(opened, conn)
		case err := <-errors:
			t.Fatalf("concurrent dial failed: %v", err)
		case <-time.After(time.Second):
			t.Fatal("initial carrier capacity did not open")
		}
	}
	select {
	case conn := <-results:
		_ = conn.Close()
		t.Fatal("session exceeded the configured physical carrier capacity")
	case err := <-errors:
		t.Fatalf("concurrent dial failed while waiting: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if got := dialer.callCount(); got != 2 {
		t.Fatalf("carrier dials at concurrency limit = %d, want 2", got)
	}

	completed := len(opened)
	for _, conn := range opened {
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for completed < callers {
		select {
		case conn := <-results:
			completed++
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		case err := <-errors:
			t.Fatalf("concurrent dial failed: %v", err)
		case <-time.After(time.Second):
			t.Fatalf("completed sessions = %d, want %d", completed, callers)
		}
	}
	if got := dialer.callCount(); got != 2 {
		t.Fatalf("carrier dials after all sessions = %d, want 2", got)
	}
}

func TestPoolCloseUnblocksMaxCarriersWait(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	options := testPoolOptions()
	options.MaxConcurrency = 1
	options.CarrierLimiter = NewCarrierLimiter(1)
	pool := NewPool(dialer.dial, options)

	first, err := pool.DialContext(context.Background(), "one.example", 80)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	result := make(chan error, 1)
	go func() {
		_, err := pool.DialContext(context.Background(), "two.example", 80)
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("wait returned before pool close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrPoolClosed) {
			t.Fatalf("wait error = %v, want %v", err, ErrPoolClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("Pool.Close did not unblock carrier capacity wait")
	}
}

func TestPoolMaxCarriersWakesAllWaitersForReusableCapacity(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	options := testPoolOptions()
	options.MaxConcurrency = 4
	options.CarrierLimiter = NewCarrierLimiter(1)
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = pool.Close() })

	active := make([]net.PacketConn, 4)
	for i := range active {
		conn, err := pool.ListenPacketContext(context.Background(), "active.example", 53, [8]byte{})
		if err != nil {
			t.Fatal(err)
		}
		active[i] = conn
	}

	const waiters = 3
	results := make(chan net.PacketConn, waiters)
	errors := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			conn, err := pool.ListenPacketContext(context.Background(), "waiting.example", 53, [8]byte{})
			if err != nil {
				errors <- err
				return
			}
			results <- conn
		}()
	}
	select {
	case conn := <-results:
		_ = conn.Close()
		t.Fatal("waiter opened while carrier was full")
	case err := <-errors:
		t.Fatalf("waiter failed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	for i := 0; i < waiters; i++ {
		if err := active[i].Close(); err != nil {
			t.Fatal(err)
		}
	}
	defer active[3].Close()
	for i := 0; i < waiters; i++ {
		select {
		case conn := <-results:
			defer conn.Close()
		case err := <-errors:
			t.Fatalf("waiter failed after capacity release: %v", err)
		case <-time.After(time.Second):
			t.Fatalf("woken waiters = %d, want %d", i, waiters)
		}
	}
	if got := dialer.callCount(); got != 1 {
		t.Fatalf("carrier dials = %d, want 1", got)
	}
}

func TestPoolSharesCarrierBetweenStreamAndPacketSessions(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	pool := NewPool(dialer.dial, testPoolOptions())
	t.Cleanup(func() { _ = pool.Close() })

	stream, err := pool.DialContext(context.Background(), "stream.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := pool.ListenPacketContext(context.Background(), "packet.example", 53, [8]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close(); _ = packetConn.Close() })

	if got := dialer.callCount(); got != 1 {
		t.Fatalf("carrier dials = %d, want 1", got)
	}
	if got := pool.activeSessions(); got != 2 {
		t.Fatalf("active sessions = %d, want 2", got)
	}
	if _, err := packetConn.WriteTo([]byte("query"), &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}); err != nil {
		t.Fatal(err)
	}
	frame, err := DecodeFrame(bytes.NewReader(dialer.carriers[0].bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if frame.SessionID != 2 || frame.Status != StatusNew || frame.Network != NetworkUDP || frame.GlobalID != [8]byte{1, 2, 3} {
		t.Fatalf("packet frame = %+v", frame)
	}
}

func TestPoolPacketSessionOutlivesDialContext(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	pool := NewPool(dialer.dial, testPoolOptions())
	t.Cleanup(func() { _ = pool.Close() })

	ctx, cancel := context.WithCancelCause(context.Background())
	packetConn, err := pool.ListenPacketContext(ctx, "packet.example", 53, [8]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	cancel(errors.New("dial completed"))

	select {
	case <-time.After(20 * time.Millisecond):
	}
	if got := pool.activeSessions(); got != 1 {
		t.Fatalf("active sessions after dial context cancellation = %d, want 1", got)
	}

	if _, err := packetConn.WriteTo([]byte("query"), &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}); err != nil {
		t.Fatal(err)
	}
	frame, err := DecodeFrame(bytes.NewReader(dialer.carriers[0].bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Status != StatusNew || string(frame.Payload) != "query" {
		t.Fatalf("packet frame after dial context cancellation = %+v", frame)
	}

	dialer.carriers[0].inject(t, Frame{
		SessionID: frame.SessionID, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
		Destination: "8.8.8.8", Port: 53, Payload: []byte("answer"),
	})
	buffer := make([]byte, 16)
	n, address, err := packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "answer" || address.String() != "8.8.8.8:53" {
		t.Fatalf("packet response = (%q, %v)", buffer[:n], address)
	}
}

func TestPoolRejectsCanceledPacketDialContext(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	pool := NewPool(dialer.dial, testPoolOptions())
	t.Cleanup(func() { _ = pool.Close() })

	cause := errors.New("packet dial canceled")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	packetConn, err := pool.ListenPacketContext(ctx, "packet.example", 53, [8]byte{})
	if packetConn != nil || !errors.Is(err, cause) {
		t.Fatalf("ListenPacketContext = (%v, %v), want (nil, %v)", packetConn, err, cause)
	}
	if got := pool.activeSessions(); got != 0 {
		t.Fatalf("active sessions after canceled dial = %d, want 0", got)
	}
}

func TestPoolRotatesAtLifetimeLimitAndUsesMonotonicIDs(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	options := testPoolOptions()
	options.MaxConnections = 2
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = pool.Close() })

	for i := 0; i < 2; i++ {
		conn, err := pool.DialContext(context.Background(), "echo.example", 443)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return pool.activeSessions() == 0 })
	}
	third, err := pool.DialContext(context.Background(), "echo.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if got := dialer.callCount(); got != 2 {
		t.Fatalf("carrier dials = %d, want 2", got)
	}

	reader := bytes.NewReader(dialer.carriers[0].bytes())
	var newIDs []uint16
	for reader.Len() > 0 {
		frame, err := DecodeFrame(reader)
		if err != nil {
			t.Fatalf("decode carrier writes: %v", err)
		}
		if frame.Status == StatusNew {
			newIDs = append(newIDs, frame.SessionID)
		}
	}
	if len(newIDs) != 2 || newIDs[0] != 1 || newIDs[1] != 2 {
		t.Fatalf("new session IDs = %v, want [1 2]", newIDs)
	}
}

func TestPoolRemovesIdleCarrierWithFakeClock(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	clock := &fakeClock{}
	options := testPoolOptions()
	options.AfterFunc = func(duration time.Duration, fn func()) Timer {
		return clock.AfterFunc(duration, fn)
	}
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = pool.Close() })

	conn, err := pool.DialContext(context.Background(), "idle.example", 80)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	waitFor(t, func() bool { return pool.activeSessions() == 0 })
	waitFor(t, func() bool { return clock.timerCount() == 1 })
	clock.FireAll()
	waitFor(t, func() bool { return pool.workerCount() == 0 })
	if !dialer.carriers[0].isClosed() {
		t.Fatal("idle carrier was not closed")
	}
}

func TestPoolDoesNotRetainFailedCarrierDial(t *testing.T) {
	dialErr := errors.New("dial failed")
	dialer := &fakeCarrierDialer{errors: []error{dialErr}}
	pool := NewPool(dialer.dial, testPoolOptions())
	t.Cleanup(func() { _ = pool.Close() })

	if _, err := pool.DialContext(context.Background(), "failure.example", 80); !errors.Is(err, dialErr) {
		t.Fatalf("first dial error = %v", err)
	}
	conn, err := pool.DialContext(context.Background(), "success.example", 80)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	_ = conn.Close()
	if got := dialer.callCount(); got != 2 {
		t.Fatalf("carrier dials = %d, want 2", got)
	}
}

func TestPoolCloseDoesNotWaitForCarrierDial(t *testing.T) {
	dialer := newBlockingCarrierDialer()
	pool := NewPool(dialer.dial, testPoolOptions())

	dialResult := make(chan error, 1)
	go func() {
		_, err := pool.DialContext(context.Background(), "blocked.example", 443)
		dialResult <- err
	}()

	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("carrier dial did not start")
	}

	closeDone := make(chan struct{})
	go func() {
		_ = pool.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(100 * time.Millisecond):
		close(dialer.release)
		<-closeDone
		<-dialResult
		t.Fatal("Pool.Close blocked on an in-flight carrier dial")
	}

	close(dialer.release)
	if err := <-dialResult; !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("dial error after pool close = %v, want %v", err, ErrPoolClosed)
	}
	if !dialer.carrier.isClosed() {
		t.Fatal("carrier completed after pool close was not closed")
	}
}

func TestPoolCoalescesConcurrentCarrierDials(t *testing.T) {
	dialer := newBlockingCarrierDialer()
	options := testPoolOptions()
	options.MaxConcurrency = 32
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = pool.Close() })

	const callers = 16
	start := make(chan struct{})
	results := make(chan net.Conn, callers)
	errors := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			ready.Done()
			<-start
			conn, err := pool.DialContext(context.Background(), "shared.example", 443)
			if err != nil {
				errors <- err
				return
			}
			results <- conn
		}()
	}
	ready.Wait()
	close(start)

	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("carrier dial did not start")
	}

	select {
	case <-time.After(100 * time.Millisecond):
		if got := dialer.callCount(); got != 1 {
			close(dialer.release)
			t.Fatalf("concurrent carrier dials = %d, want 1", got)
		}
	}
	close(dialer.release)

	for i := 0; i < callers; i++ {
		select {
		case err := <-errors:
			t.Fatalf("concurrent dial failed: %v", err)
		case conn := <-results:
			_ = conn.Close()
		case <-time.After(time.Second):
			t.Fatal("concurrent dial did not complete")
		}
	}
	if got := dialer.callCount(); got != 1 {
		t.Fatalf("carrier dials = %d, want 1", got)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition was not satisfied before timeout")
	}
}
