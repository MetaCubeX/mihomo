package sudoku

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"
)

type mockConn struct {
	readBuf  []byte
	writeBuf []byte
}

func (c *mockConn) Read(p []byte) (int, error) {
	if len(c.readBuf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *mockConn) Write(p []byte) (int, error) {
	c.writeBuf = append(c.writeBuf, p...)
	return len(p), nil
}

func (c *mockConn) Close() error                     { return nil }
func (c *mockConn) LocalAddr() net.Addr              { return nil }
func (c *mockConn) RemoteAddr() net.Addr             { return nil }
func (c *mockConn) SetDeadline(time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(time.Time) error { return nil }

func TestPackedConn_ProtectedPrefixPadding(t *testing.T) {
	table := NewTable("packed-prefix-seed", "prefer_ascii")
	mock := &mockConn{}
	writer := NewPackedConn(mock, table, 0, 0)
	writer.rng = rand.New(rand.NewSource(1))

	payload := bytes.Repeat([]byte{0}, 32)
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	wire := append([]byte(nil), mock.writeBuf...)
	if len(wire) < 20 {
		t.Fatalf("wire too short: %d", len(wire))
	}

	firstHint := -1
	nonHintCount := 0
	maxHintRun := 0
	currentHintRun := 0
	for i, b := range wire[:20] {
		if table.layout.isHint(b) {
			if firstHint == -1 {
				firstHint = i
			}
			currentHintRun++
			if currentHintRun > maxHintRun {
				maxHintRun = currentHintRun
			}
			continue
		}
		nonHintCount++
		currentHintRun = 0
	}

	if firstHint < 1 || firstHint > 2 {
		t.Fatalf("expected 1-2 leading padding bytes, first hint index=%d", firstHint)
	}
	if nonHintCount < 6 {
		t.Fatalf("expected dense prefix padding, got only %d non-hint bytes in first 20", nonHintCount)
	}
	if maxHintRun > 3 {
		t.Fatalf("prefix still exposes long hint run: %d", maxHintRun)
	}

	reader := NewPackedConn(&mockConn{readBuf: wire}, table, 0, 0)
	decoded := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, decoded); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("roundtrip mismatch")
	}
}
