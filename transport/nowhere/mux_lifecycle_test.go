package nowhere

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func writeTestMuxFrame(t *testing.T, c net.Conn, kind byte, id uint32, payload []byte) {
	t.Helper()
	b := make([]byte, 7+len(payload))
	b[0] = kind
	binary.BigEndian.PutUint16(b[1:], uint16(len(payload)))
	binary.BigEndian.PutUint32(b[3:], id)
	copy(b[7:], payload)
	if err := writeFull(c, b); err != nil {
		t.Fatal(err)
	}
}

func readTestMuxFrame(t *testing.T, c net.Conn) muxFrame {
	t.Helper()
	var h [7]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		t.Fatal(err)
	}
	f := muxFrame{kind: h[0], value: binary.BigEndian.Uint16(h[1:]), id: binary.BigEndian.Uint32(h[3:])}
	if f.kind == muxData {
		f.payload = make([]byte, f.value)
		if _, err := io.ReadFull(c, f.payload); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestMuxReusedID(t *testing.T) {
	for _, terminal := range []byte{muxReset, muxFIN} {
		t.Run(map[byte]string{muxReset: "reset", muxFIN: "fin"}[terminal], func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			_ = b.SetDeadline(time.Now().Add(5 * time.Second))
			incoming := make(chan *muxStream, 2)
			m := newMux(a, func(s *muxStream) { incoming <- s })
			defer m.Close()
			writeTestMuxFrame(t, b, muxOpen, 1, nil)
			old := <-incoming
			defer old.Close()
			writeTestMuxFrame(t, b, muxData, 1, []byte("old"))
			if terminal == muxFIN {
				old.CloseWrite()
				if f := readTestMuxFrame(t, b); f.kind != muxFIN {
					t.Fatalf("expected FIN: %+v", f)
				}
			}
			writeTestMuxFrame(t, b, terminal, 1, nil)
			writeTestMuxFrame(t, b, muxOpen, 1, nil)
			current := <-incoming
			defer current.Close()
			if terminal == muxReset {
				if data, err := io.ReadAll(old); err != nil || string(data) != "old" {
					t.Fatalf("lost pre-RESET data: %q, %v", data, err)
				}
			}
			// RESET drains buffered data; FIN exercises discarding unread data.
			old.Close()
			m.mu.Lock()
			registered, active, recv := m.streams[1] == current, m.active, m.recv
			m.mu.Unlock()
			if !registered || active != 1 || recv != connWindow {
				t.Fatalf("old cleanup affected new stream: registered=%v active=%d recv=%d", registered, active, recv)
			}
			if f := readTestMuxFrame(t, b); f.kind != muxWindow || f.id != 0 || f.value != 1 {
				t.Fatalf("old stream must return only connection credit: %+v", f)
			}
			current.CloseWrite()
			if f := readTestMuxFrame(t, b); f.kind != muxFIN {
				t.Fatalf("unexpected stale frame before FIN: %+v", f)
			}
			writeTestMuxFrame(t, b, muxData, 1, []byte("new"))
			var data [3]byte
			_ = current.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(current, data[:]); err != nil || string(data[:]) != "new" {
				t.Fatalf("reused stream failed: %q, %v", data, err)
			}
		})
	}
}

func TestMuxDropsQueuedCreditAfterReset(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	wire := &delayedMuxWriteConn{Conn: a, payload: []byte("hold"), release: make(chan struct{})}
	incoming := make(chan *muxStream, 2)
	m := newMux(wire, func(s *muxStream) { incoming <- s })
	defer m.Close()
	writeTestMuxFrame(t, b, muxOpen, 1, nil)
	old := <-incoming
	defer old.Close()
	written := make(chan error, 1)
	go func() { _, err := old.Write(wire.payload); written <- err }()
	if f := readTestMuxFrame(t, b); f.kind != muxData || string(f.payload) != "hold" {
		t.Fatalf("expected in-flight write: %+v", f)
	}
	writeTestMuxFrame(t, b, muxData, 1, []byte{42})
	var data [1]byte
	_ = old.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(old, data[:]); err != nil {
		t.Fatal(err)
	}
	// Both WINDOW updates are queued behind the paused carrier writer.
	writeTestMuxFrame(t, b, muxReset, 1, nil)
	writeTestMuxFrame(t, b, muxOpen, 1, nil)
	current := <-incoming
	defer current.Close()
	wire.unblock()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if f := readTestMuxFrame(t, b); f.kind != muxWindow || f.id != 0 || f.value != 1 {
		t.Fatalf("stale queued stream credit: %+v", f)
	}
	current.CloseWrite()
	if f := readTestMuxFrame(t, b); f.kind != muxFIN {
		t.Fatalf("stale queued frame before FIN: %+v", f)
	}
}
