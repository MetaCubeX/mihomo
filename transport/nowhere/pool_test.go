package nowhere

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestMuxPendingOpenLimit(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	release := make(chan struct{})
	defer close(release)
	m := newMux(a, func(s *muxStream) { <-release; s.Close() })
	defer m.Close()
	_ = b.SetWriteDeadline(time.Now().Add(3 * time.Second))
	for id := uint32(1); id <= 4097; id++ {
		var frame [7]byte
		frame[0] = muxOpen
		binary.BigEndian.PutUint32(frame[3:], id)
		if err := writeFull(b, frame[:]); err != nil {
			break
		}
		frame[0] = muxReset
		if err := writeFull(b, frame[:]); err != nil {
			break
		}
	}
	select {
	case <-m.done:
	case <-time.After(time.Second):
		t.Fatal("OPEN/RESET bypassed pending delivery limit")
	}
}

func TestMuxRetiresClosedStateBudget(t *testing.T) {
	c := testClient(t, "127.0.0.1:1", "tcp", "tcp", true, false)
	replaced := errors.New("replacement dial")
	c.config.DialTCP = func(context.Context) (net.Conn, error) { return nil, replaced }
	for i := 0; i < 8; i++ {
		a, b := net.Pipe()
		defer b.Close()
		m := newMux(a, nil)
		defer m.Close()
		// State retained after local RESET, with no application owners left.
		m.mu.Lock()
		for id := uint32(1); id <= 4096; id++ {
			s := m.stream(id)
			s.closed = true
			close(s.done)
		}
		m.active = 0
		m.mu.Unlock()
		c.mux = append(c.mux, m)
	}
	if _, err := c.acquire(context.Background(), carrierTLS, 5000); !errors.Is(err, replaced) {
		t.Fatalf("full closed carriers were not replaced: %v", err)
	}
}

func TestMuxRetirementDrainsActiveStream(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	go io.Copy(io.Discard, b)
	m := newMux(a, nil)
	defer m.Close()
	m.mu.Lock()
	for id := uint32(1); id < 4096; id++ {
		s := m.stream(id)
		s.closed = true
		close(s.done)
	}
	s := m.stream(4096)
	m.active = 1
	m.mu.Unlock()
	if active, _, usable := m.poolLoad(5000); active != 1 || usable {
		t.Fatal("full carrier still admits flows")
	}
	select {
	case <-m.done:
		t.Fatal("retirement interrupted active stream")
	default:
	}
	if _, err := s.Write([]byte("still active")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	select {
	case <-m.done:
	case <-time.After(time.Second):
		t.Fatal("drained carrier stayed open")
	}
}

func TestMuxParallelDialLimitAndCancellation(t *testing.T) {
	c := testClient(t, "127.0.0.1:1", "tcp", "tcp", true, false)
	entered := make(chan struct{}, 16)
	c.config.DialTCP = func(ctx context.Context) (net.Conn, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for id := uint32(1); id <= 8; id++ {
		id := id
		wg.Add(1)
		go func() { defer wg.Done(); c.acquire(ctx, carrierTLS, id) }()
	}
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("Mux initializers were serialized")
		}
	}
	waitCtx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	finished := make(chan error, 1)
	go func() { _, err := c.acquire(waitCtx, carrierTLS, 9); finished <- err }()
	select {
	case err := <-finished:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pool waiter ignored deadline")
	}
	select {
	case <-entered:
		t.Fatal("more than eight connecting carriers")
	default:
	}
	cancel()
	wg.Wait()
	c.mmu.Lock()
	defer c.mmu.Unlock()
	if c.muxConnecting != 0 {
		t.Fatal("connecting reservations leaked")
	}
}

func TestMuxRetirementWakesWaiters(t *testing.T) {
	c := testClient(t, "127.0.0.1:1", "tcp", "tcp", true, false)
	replaced := errors.New("replacement dial")
	c.config.DialTCP = func(context.Context) (net.Conn, error) { return nil, replaced }
	var first *muxStream
	for i := 0; i < 8; i++ {
		a, b := net.Pipe()
		defer b.Close()
		m := newMux(a, nil)
		defer m.Close()
		m.mu.Lock()
		s := m.stream(1)
		m.retiring = true
		m.mu.Unlock()
		if first == nil {
			first = s
		}
		c.mux = append(c.mux, m)
		c.watchMux(m)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := c.acquire(ctx, carrierTLS, 2); finished <- err }()
	select {
	case err := <-finished:
		t.Fatalf("did not wait for draining carriers: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	first.Close() // Not the last carrier inspected by the pool.
	select {
	case err := <-finished:
		if !errors.Is(err, replaced) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("retirement did not wake pool waiter")
	}
}

func TestClientCloseCancelsInitializers(t *testing.T) {
	for _, carrier := range []byte{carrierTLS, carrierQUIC} {
		t.Run(map[byte]string{carrierTLS: "mux", carrierQUIC: "quic"}[carrier], func(t *testing.T) {
			c := testClient(t, "127.0.0.1:1", "tcp", "tcp", true, false)
			entered := make(chan struct{})
			dial := func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }
			c.config.DialTCP = func(ctx context.Context) (net.Conn, error) { return nil, dial(ctx) }
			c.config.DialUDP = func(ctx context.Context) (net.PacketConn, net.Addr, error) { return nil, nil, dial(ctx) }
			finished := make(chan error, 1)
			go func() { _, err := c.acquire(context.Background(), carrier, 1); finished <- err }()
			<-entered
			c.Close()
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("initializer survived client close")
				}
			case <-time.After(time.Second):
				t.Fatal("client close did not cancel initializer")
			}
		})
	}
}

func testUDPServer(t *testing.T) string {
	t.Helper()
	s, err := NewServer(ServerConfig{Password: "secret", TLSConfig: testCertificate(t), Handler: echoHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ServeUDP(pc); err != nil {
		t.Fatal(err)
	}
	return pc.LocalAddr().String()
}

func TestQUICInitializerCancellationAndRetry(t *testing.T) {
	c := testClient(t, testUDPServer(t), "udp", "udp", false, false)
	dial := c.config.DialUDP
	entered := make(chan struct{})
	first := true // QUIC initializers are serialized, not their waiters.
	c.config.DialUDP = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		if first {
			first = false
			close(entered)
			<-ctx.Done()
			return nil, nil, ctx.Err()
		}
		return dial(ctx)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := make(chan error, 1)
	go func() { _, err := c.getQUIC(ctx); owner <- err }()
	<-entered
	waitCtx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	waiter := make(chan error, 1)
	go func() { _, err := c.getQUIC(waitCtx); waiter <- err }()
	select {
	case err := <-waiter:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("QUIC waiter ignored deadline")
	}
	cancel()
	if err := <-owner; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	retryCtx, stopRetry := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopRetry()
	if _, err := c.getQUIC(retryCtx); err != nil {
		t.Fatalf("cancelled initializer was not retryable: %v", err)
	}
}
