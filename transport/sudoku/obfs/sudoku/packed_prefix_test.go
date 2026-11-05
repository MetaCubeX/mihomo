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
	writer.rng = newSudokuRand(1)

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

func TestCodecRoundTrip(t *testing.T) {
	tables := map[string]*Table{
		"entropy": NewTable("roundtrip-seed", "prefer_entropy"),
		"ascii":   NewTable("roundtrip-seed", "prefer_ascii"),
	}
	custom, err := NewTableWithCustom("roundtrip-seed", "up_ascii_down_entropy", "xpxvvpvv")
	if err != nil {
		t.Fatal(err)
	}
	tables["custom"] = custom.OppositeDirection()

	for name, table := range tables {
		for _, packed := range []bool{false, true} {
			for _, pad := range [][2]int{{0, 0}, {5, 15}, {100, 100}} {
				for _, size := range []int{1, 2, 14, 15, 100, 70000} {
					payload := make([]byte, size)
					rand.New(rand.NewSource(int64(size))).Read(payload)

					mock := &mockConn{}
					var w io.Writer = NewConn(mock, table, pad[0], pad[1], false)
					if packed {
						w = NewPackedConn(mock, table, pad[0], pad[1])
					}
					// Split the payload so partial packed groups carry over between writes.
					if _, err := w.Write(payload[:size/2]); err != nil {
						t.Fatal(err)
					}
					if _, err := w.Write(payload[size/2:]); err != nil {
						t.Fatal(err)
					}
					if f, ok := w.(*PackedConn); ok {
						if err := f.Flush(); err != nil {
							t.Fatal(err)
						}
					}

					for _, readSize := range []int{1, 7, 4096} {
						src := &mockConn{readBuf: append([]byte(nil), mock.writeBuf...)}
						var r io.Reader = NewConn(src, table, pad[0], pad[1], false)
						if packed {
							r = NewPackedConn(src, table, pad[0], pad[1])
						}
						got := make([]byte, 0, size)
						buf := make([]byte, readSize)
						for {
							n, err := r.Read(buf)
							got = append(got, buf[:n]...)
							if err == io.EOF {
								break
							}
							if err != nil {
								t.Fatal(err)
							}
						}
						if !bytes.Equal(got, payload) {
							t.Fatalf("%s packed=%v pad=%v size=%d read=%d: round trip mismatch", name, packed, pad, size, readSize)
						}
					}
				}
			}
		}
	}
}

func TestConnRecordsEverythingRead(t *testing.T) {
	table := NewTable("record-seed", "prefer_entropy")
	writer := &mockConn{}
	payload := bytes.Repeat([]byte("sudoku"), 3000)
	if _, err := NewConn(writer, table, 5, 15, false).Write(payload); err != nil {
		t.Fatal(err)
	}
	wire := writer.writeBuf

	src := &mockConn{readBuf: append([]byte(nil), wire...)}
	sc := NewConn(src, table, 5, 15, true)
	buf := make([]byte, 200)
	for step := 0; step < 3; step++ {
		if _, err := io.ReadFull(sc, buf); err != nil {
			t.Fatal(err)
		}
		// Recorded plus buffered must be every byte taken from the socket, whatever
		// the reader has or has not decoded yet.
		if got, want := sc.GetBufferedAndRecorded(), wire[:len(wire)-len(src.readBuf)]; !bytes.Equal(got, want) {
			t.Fatalf("step %d: recorded %d bytes, want %d", step, len(got), len(want))
		}
	}
	if !sc.reader.pooled {
		t.Fatalf("a busy connection should have switched to a pooled read buffer")
	}

	sc.StopRecording()
	if _, err := io.Copy(io.Discard, sc); err != nil {
		t.Fatal(err)
	}
	if sc.reader.pooled || len(sc.reader.pending()) != 0 {
		t.Fatalf("a drained connection should hold no pooled buffer")
	}
	if got := sc.GetBufferedAndRecorded(); len(got) != 0 {
		t.Fatalf("recording was stopped, got %d bytes", len(got))
	}
}
