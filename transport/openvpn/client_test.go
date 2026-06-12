package openvpn

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeControlStream struct {
	readCh  chan []byte
	writeCh chan []byte

	mu           sync.Mutex
	readDeadline time.Time
	closed       bool
}

func newFakeControlStream() *fakeControlStream {
	return &fakeControlStream{
		readCh:  make(chan []byte, 8),
		writeCh: make(chan []byte, 8),
	}
}

func (f *fakeControlStream) Read(b []byte) (int, error) {
	f.mu.Lock()
	deadline := f.readDeadline
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if deadline.IsZero() {
		msg, ok := <-f.readCh
		if !ok {
			return 0, net.ErrClosed
		}
		return copy(b, msg), nil
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case msg, ok := <-f.readCh:
		if !ok {
			return 0, net.ErrClosed
		}
		return copy(b, msg), nil
	case <-timer.C:
		return 0, timeoutError{}
	}
}

func (f *fakeControlStream) Write(b []byte) (int, error) {
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	f.writeCh <- cloneBytes(b)
	return len(b), nil
}

func (f *fakeControlStream) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.readDeadline = t
	f.mu.Unlock()
	return nil
}

func (f *fakeControlStream) SetWriteDeadline(time.Time) error {
	return nil
}

func (f *fakeControlStream) Close() {
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		close(f.readCh)
	}
	f.mu.Unlock()
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestRunControlLoopSendsPing(t *testing.T) {
	stream := newFakeControlStream()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runControlLoop(ctx, stream, &PushReply{
			PingInterval: 20 * time.Millisecond,
			PingRestart:  200 * time.Millisecond,
		}, "test", newRemoteActivity())
	}()

	select {
	case msg := <-stream.writeCh:
		if got := string(msg); got != "PING\x00" {
			t.Fatalf("unexpected ping payload: %q", got)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("control loop did not send PING")
	}

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestRunControlLoopRestartsOnPingTimeout(t *testing.T) {
	stream := newFakeControlStream()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := runControlLoop(ctx, stream, &PushReply{PingRestart: 30 * time.Millisecond}, "test", newRemoteActivity())
	if !errors.Is(err, ErrControlRestart) {
		t.Fatalf("expected restart on ping timeout, got %v", err)
	}
	if !strings.Contains(err.Error(), "ping-restart") {
		t.Fatalf("expected ping-restart reason, got %v", err)
	}
}

func TestRunControlLoopRestartsOnServerRestartMessage(t *testing.T) {
	stream := newFakeControlStream()
	stream.readCh <- []byte("RESTART,soft\x00")

	err := runControlLoop(context.Background(), stream, &PushReply{}, "test", newRemoteActivity())
	if !errors.Is(err, ErrControlRestart) {
		t.Fatalf("expected restart on server RESTART, got %v", err)
	}
}

func TestRunControlLoopReturnsAuthFailure(t *testing.T) {
	stream := newFakeControlStream()
	stream.readCh <- []byte("AUTH_FAILED,denied\x00")

	err := runControlLoop(context.Background(), stream, &PushReply{}, "test", newRemoteActivity())
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected auth failure, got %v", err)
	}
}

func TestRunControlLoopDataActivityPreventsPingRestart(t *testing.T) {
	stream := newFakeControlStream()
	activity := newRemoteActivity()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runControlLoop(ctx, stream, &PushReply{PingRestart: 60 * time.Millisecond}, "test", activity)
	}()

	time.Sleep(40 * time.Millisecond)
	activity.Mark()

	select {
	case err := <-errCh:
		t.Fatalf("control loop stopped despite data-channel activity: %v", err)
	case <-time.After(40 * time.Millisecond):
	}

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}
