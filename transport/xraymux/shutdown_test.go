package xraymux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestClosingOneSessionKeepsSiblingAlive(t *testing.T) {
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 8, 128, nil)
	t.Cleanup(func() { worker.close(nil) })
	first, err := worker.openSession(context.Background(), "first.example", 80, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := worker.openSession(context.Background(), "second.example", 80, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return worker.activeSessions() == 1 })
	carrier.inject(t, Frame{SessionID: 2, Status: StatusKeep, Option: OptionData, Payload: []byte("alive")})
	got := make([]byte, len("alive"))
	if _, err := io.ReadFull(second, got); err != nil {
		t.Fatalf("read sibling: %v", err)
	}
	if string(got) != "alive" {
		t.Fatalf("sibling response = %q", got)
	}
}

func TestSessionContextAndRepeatedCloseSendOneEnd(t *testing.T) {
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 8, 128, nil)
	t.Cleanup(func() { worker.close(nil) })
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := worker.openSession(ctx, "cancel.example", 80, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	_ = conn.Close()
	_ = conn.Close()
	waitFor(t, func() bool { return worker.activeSessions() == 0 })

	reader := bytes.NewReader(carrier.bytes())
	endCount := 0
	for reader.Len() > 0 {
		frame, err := DecodeFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		if frame.SessionID == 1 && frame.Status == StatusEnd {
			endCount++
		}
	}
	if endCount != 1 {
		t.Fatalf("End count = %d, want 1", endCount)
	}
}

func TestSimultaneousSessionCarrierPoolAndContextShutdown(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	options := testPoolOptions()
	options.MaxConcurrency = 32
	pool := NewPool(dialer.dial, options)

	const sessionCount = 16
	connections := make([]net.Conn, 0, sessionCount)
	cancels := make([]context.CancelFunc, 0, sessionCount)
	for i := 0; i < sessionCount; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		conn, err := pool.DialContext(ctx, "shutdown.example", 443)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		cancels = append(cancels, cancel)
	}

	var wg sync.WaitGroup
	for index := range connections {
		wg.Add(2)
		go func(index int) {
			defer wg.Done()
			cancels[index]()
		}(index)
		go func(index int) {
			defer wg.Done()
			_ = connections[index].Close()
		}(index)
	}
	wg.Add(3)
	go func() { defer wg.Done(); _ = dialer.carriers[0].Close() }()
	go func() { defer wg.Done(); _ = pool.Close() }()
	go func() { defer wg.Done(); _ = pool.Close() }()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("simultaneous shutdown deadlocked")
	}
	if _, err := pool.DialContext(context.Background(), "closed.example", 80); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("dial after close error = %v", err)
	}
}
