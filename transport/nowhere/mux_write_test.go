package nowhere

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Pause a completed socket write before the Mux writer can publish completion.
type delayedMuxWriteConn struct {
	net.Conn
	payload []byte
	release chan struct{}
	once    sync.Once
}

func (c *delayedMuxWriteConn) unblock()     { c.once.Do(func() { close(c.release) }) }
func (c *delayedMuxWriteConn) Close() error { c.unblock(); return c.Conn.Close() }
func (c *delayedMuxWriteConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil && bytes.Equal(b, c.payload) {
		<-c.release
	}
	return n, err
}

func TestMuxResetAfterDeliveredWrite(t *testing.T) {
	testMuxDeliveredWrite(t, false)
}

func TestMuxLocalCloseAfterDeliveredWrite(t *testing.T) {
	testMuxDeliveredWrite(t, true)
}

func testMuxDeliveredWrite(t *testing.T, closeLocal bool) {
	t.Helper()
	a, b := net.Pipe()
	wire := &delayedMuxWriteConn{Conn: a, payload: []byte("attach"), release: make(chan struct{})}
	client := newMux(wire, nil)
	defer client.Close()
	server := newMux(b, func(s *muxStream) {
		defer s.Close()
		buf := make([]byte, len(wire.payload))
		if _, err := io.ReadFull(s, buf); err == nil {
			_, _ = s.Write([]byte{DialFailed})
		}
	})
	defer server.Close()
	s, err := client.Open(1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(3 * time.Second))
	written := make(chan error, 1)
	go func() { _, err := s.Write(wire.payload); written <- err }()
	select {
	case <-s.done: // the response and RESET have both arrived
	case <-time.After(3 * time.Second):
		t.Fatal("peer did not reset")
	}
	if closeLocal {
		_ = s.Close()
		select {
		case err := <-written:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("local close: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("local close did not interrupt queued write")
		}
		return
	}
	select {
	case err := <-written:
		t.Fatalf("remote RESET superseded a delivered write: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	wire.unblock()
	if err = <-written; err != nil {
		t.Fatal(err)
	}
	if err = readResult(s); err != SetupError(DialFailed) {
		t.Fatalf("lost setup result: %v", err)
	}
}
