package sudoku

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func FuzzConnRoundTrip(f *testing.F) {
	table := NewTable("fuzz-key", "prefer_entropy")
	f.Add([]byte("hello"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256 {
			data = data[:256]
		}

		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		writer := NewConn(c1, table, 0, 0, false)
		reader := NewConn(c2, table, 0, 0, false)

		writeErr := make(chan error, 1)
		go func() {
			_, err := writer.Write(data)
			_ = c1.Close()
			writeErr <- err
		}()

		got := make([]byte, len(data))
		if _, err := io.ReadFull(reader, got); err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if err := <-writeErr; err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("roundtrip mismatch")
		}
	})
}
