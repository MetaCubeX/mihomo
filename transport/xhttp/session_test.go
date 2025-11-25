package xhttp

import (
	"io"
	"testing"
	"time"
)

func TestUploadQueueReordering(t *testing.T) {
	uq := newUploadQueue(10)
	defer uq.Close()

	packets := []Packet{
		{Payload: []byte("packet2"), Seq: 2},
		{Payload: []byte("packet0"), Seq: 0},
		{Payload: []byte("packet3"), Seq: 3},
		{Payload: []byte("packet1"), Seq: 1},
	}

	for _, p := range packets {
		if err := uq.Push(p); err != nil {
			t.Fatalf("Push failed: %v", err)
		}
	}

	buf := make([]byte, 100)
	expected := []string{"packet0", "packet1", "packet2", "packet3"}

	for i, exp := range expected {
		n, err := uq.Read(buf)
		if err != nil {
			t.Fatalf("Read %d failed: %v", i, err)
		}
		if string(buf[:n]) != exp {
			t.Errorf("Read %d: expected %s, got %s", i, exp, string(buf[:n]))
		}
	}
}

func TestUploadQueueStreamMode(t *testing.T) {
	uq := newUploadQueue(10)
	defer uq.Close()

	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("stream data"))
		pw.Close()
	}()

	if err := uq.Push(Packet{Reader: pr, Seq: 0}); err != nil {
		t.Fatalf("Push stream failed: %v", err)
	}

	buf := make([]byte, 100)
	n, err := uq.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != "stream data" {
		t.Errorf("Expected 'stream data', got %s", string(buf[:n]))
	}
}

func TestUploadQueueBufferLimit(t *testing.T) {
	uq := newUploadQueue(2)
	defer uq.Close()

	for i := 0; i < 64; i++ {
		uq.Push(Packet{Payload: []byte("x"), Seq: uint64(i)})
	}

	time.Sleep(10 * time.Millisecond)

	for i := 0; i < 10; i++ {
		if err := uq.Push(Packet{Payload: []byte("overflow"), Seq: uint64(100 + i)}); err != io.ErrShortBuffer {
			t.Errorf("Expected ErrShortBuffer, got %v", err)
		}
	}
}

func TestUploadQueueClose(t *testing.T) {
	uq := newUploadQueue(10)

	uq.Push(Packet{Payload: []byte("data"), Seq: 0})
	time.Sleep(10 * time.Millisecond)

	buf := make([]byte, 100)
	n, err := uq.Read(buf)
	if err != nil {
		t.Fatalf("Read before close should succeed: %v", err)
	}
	if string(buf[:n]) != "data" {
		t.Errorf("Expected 'data', got %s", string(buf[:n]))
	}

	uq.Close()

	_, err = uq.Read(buf)
	if err != io.EOF {
		t.Errorf("Expected EOF after close, got %v", err)
	}

	if err := uq.Push(Packet{Payload: []byte("x"), Seq: 1}); err != io.ErrClosedPipe {
		t.Errorf("Push after close should return ErrClosedPipe, got %v", err)
	}
}

func TestUploadQueueOutOfOrder(t *testing.T) {
	uq := newUploadQueue(10)
	defer uq.Close()

	uq.Push(Packet{Payload: []byte("5"), Seq: 5})
	uq.Push(Packet{Payload: []byte("3"), Seq: 3})
	uq.Push(Packet{Payload: []byte("1"), Seq: 1})

	done := make(chan bool)
	go func() {
		time.Sleep(50 * time.Millisecond)
		uq.Push(Packet{Payload: []byte("0"), Seq: 0})
		uq.Push(Packet{Payload: []byte("2"), Seq: 2})
		uq.Push(Packet{Payload: []byte("4"), Seq: 4})
		close(done)
	}()

	buf := make([]byte, 100)
	for i := 0; i < 6; i++ {
		n, err := uq.Read(buf)
		if err != nil {
			t.Fatalf("Read %d failed: %v", i, err)
		}
		expected := string(rune('0' + i))
		if string(buf[:n]) != expected {
			t.Errorf("Read %d: expected %s, got %s", i, expected, string(buf[:n]))
		}
	}

	<-done
}

func TestUploadQueueTimeout(t *testing.T) {
	uq := newUploadQueue(10)
	defer uq.Close()

	done := make(chan error)
	go func() {
		buf := make([]byte, 100)
		_, err := uq.Read(buf)
		done <- err
	}()

	start := time.Now()
	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err != io.ErrNoProgress {
			t.Errorf("Expected ErrNoProgress, got %v", err)
		}
		if elapsed < 90*time.Millisecond || elapsed > 150*time.Millisecond {
			t.Errorf("Expected timeout ~100ms, got %v", elapsed)
		}
	case <-time.After(200 * time.Millisecond):
		return
	}
}

func TestHTTPSessionClose(t *testing.T) {
	session := newHTTPSession("test-session", 10)

	if session.closed.Load() {
		t.Error("New session should not be closed")
	}

	session.close()

	if !session.closed.Load() {
		t.Error("Session should be closed after close()")
	}

	session.close()
	if !session.closed.Load() {
		t.Error("Multiple close() should be safe")
	}
}

func TestHTTPSessionExpiry(t *testing.T) {
	session := newHTTPSession("test-session", 10)
	session.expiry = time.Now().Add(-1 * time.Hour)

	if !session.isExpired(time.Now()) {
		t.Error("Session should be expired")
	}

	session.expiry = time.Now().Add(1 * time.Hour)
	if session.isExpired(time.Now()) {
		t.Error("Session should not be expired")
	}

	session.expiry = time.Time{}
	if session.isExpired(time.Now()) {
		t.Error("Zero expiry should never expire")
	}
}
