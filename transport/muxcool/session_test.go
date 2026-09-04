package muxcool

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeSessionOwner struct {
	frames  chan Frame
	removed chan uint16
	err     error
	mu      sync.Mutex
}

func newFakeSessionOwner() *fakeSessionOwner {
	return &fakeSessionOwner{
		frames:  make(chan Frame, 32),
		removed: make(chan uint16, 8),
	}
}

func (o *fakeSessionOwner) writeFrame(frame Frame) error {
	o.mu.Lock()
	err := o.err
	o.mu.Unlock()
	if err != nil {
		return err
	}
	o.frames <- frame
	return nil
}

func (o *fakeSessionOwner) removeSession(id uint16) {
	o.removed <- id
}

func receiveFrame(t *testing.T, frames <-chan Frame) Frame {
	t.Helper()
	select {
	case frame := <-frames:
		return frame
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for frame")
		return Frame{}
	}
}

func TestLogicalSessionIsFullDuplexAndHasAddresses(t *testing.T) {
	owner := newFakeSessionOwner()
	conn, session := newSession(context.Background(), owner, 11, "echo.example", 443, time.Second)
	t.Cleanup(func() { _ = conn.Close() })

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("upload"))
		writeDone <- err
	}()
	frame := receiveFrame(t, owner.frames)
	if frame.Status != StatusNew || string(frame.Payload) != "upload" {
		t.Fatalf("uplink frame = status %d payload %q", frame.Status, frame.Payload)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := session.deliver([]byte("download")); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	got := make([]byte, len("download"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "download" {
		t.Fatalf("download = %q", got)
	}
	if conn.LocalAddr() == nil || conn.RemoteAddr() == nil || conn.RemoteAddr().String() != "echo.example:443" {
		t.Fatalf("addresses = local %v remote %v", conn.LocalAddr(), conn.RemoteAddr())
	}
	if conn.LocalAddr().Network() != "mux.cool" || conn.RemoteAddr().Network() != "mux.cool" {
		t.Fatalf("address networks = local %q remote %q", conn.LocalAddr().Network(), conn.RemoteAddr().Network())
	}
}

func TestLogicalSessionDeadlines(t *testing.T) {
	owner := newFakeSessionOwner()
	conn, _ := newSession(context.Background(), owner, 12, "deadline.example", 80, time.Second)
	t.Cleanup(func() { _ = conn.Close() })

	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("read error = %v, want timeout", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear read deadline: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := conn.Write([]byte("x")); !isTimeout(err) {
		t.Fatalf("write error = %v, want timeout", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func TestLogicalSessionCancellationAndCloseAreIdempotent(t *testing.T) {
	owner := newFakeSessionOwner()
	ctx, cancel := context.WithCancel(context.Background())
	conn, _ := newSession(ctx, owner, 13, "cancel.example", 80, time.Second)
	cancel()

	select {
	case id := <-owner.removed:
		if id != 13 {
			t.Fatalf("removed session = %d", id)
		}
	case <-time.After(time.Second):
		t.Fatal("session was not removed after cancellation")
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("read succeeded after cancellation")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestSessionFrameStateMachine(t *testing.T) {
	owner := newFakeSessionOwner()
	conn, _ := newSession(context.Background(), owner, 21, "state.example", 8080, time.Second)

	if _, err := conn.Write([]byte("first")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	first := receiveFrame(t, owner.frames)
	if first.Status != StatusNew || first.Destination != "state.example" || first.Port != 8080 {
		t.Fatalf("first frame = %+v", first)
	}
	if _, err := conn.Write([]byte("second")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	second := receiveFrame(t, owner.frames)
	if second.Status != StatusKeep || second.Destination != "" {
		t.Fatalf("second frame = %+v", second)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	end := receiveFrame(t, owner.frames)
	if end.Status != StatusEnd || end.SessionID != 21 {
		t.Fatalf("end frame = %+v", end)
	}
	select {
	case extra := <-owner.frames:
		t.Fatalf("unexpected extra frame: %+v", extra)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestSessionSendsPayloadFreeNewForServerFirstProtocol(t *testing.T) {
	owner := newFakeSessionOwner()
	conn, _ := newSession(context.Background(), owner, 22, "server-first.example", 25, 5*time.Millisecond)
	t.Cleanup(func() { _ = conn.Close() })

	frame := receiveFrame(t, owner.frames)
	if frame.Status != StatusNew || frame.Option&OptionData != 0 || len(frame.Payload) != 0 {
		t.Fatalf("payload-free new = %+v", frame)
	}
}
