package xraymux

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
