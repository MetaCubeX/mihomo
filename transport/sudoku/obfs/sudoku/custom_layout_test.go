package sudoku

import (
	"bytes"
	"io"
	"math/bits"
	"net"
	"testing"
)

func TestCustomLayoutParsingAndPadding(t *testing.T) {
	table, err := NewTableWithCustom("seed-custom", "prefer_entropy", "xpxvvpvv")
	if err != nil {
		t.Fatalf("failed to build table: %v", err)
	}
	if table.IsASCII {
		t.Fatalf("custom table should not be marked ASCII")
	}
	if table.layout == nil || table.layout.hintMask == 0 {
		t.Fatalf("layout mask not initialized")
	}

	for _, b := range table.PaddingPool {
		if table.layout.isHint(b) {
			t.Fatalf("padding byte incorrectly recognized as hint: %08b", b)
		}
		if bits.OnesCount8(b) < 5 {
			t.Fatalf("padding hamming weight too low: %d", bits.OnesCount8(b))
		}
	}
}

func TestCustomLayoutAsciiPriority(t *testing.T) {
	table, err := NewTableWithCustom("seed-custom", "prefer_ascii", "vpxxvpvv")
	if err != nil {
		t.Fatalf("failed to build ascii-preferred table: %v", err)
	}
	if !table.IsASCII {
		t.Fatalf("ascii preference should override custom pattern")
	}
	if table.layout.name != "ascii" {
		t.Fatalf("expected ascii layout, got %s", table.layout.name)
	}

	defaultTable, err := NewTableWithCustom("seed-custom", "prefer_ascii", "")
	if err != nil {
		t.Fatalf("failed to build default ascii table: %v", err)
	}
	if table.Hint() != defaultTable.Hint() {
		t.Fatalf("ascii hint should ignore custom pattern: got %d want %d", table.Hint(), defaultTable.Hint())
	}
}

func TestCustomLayoutDirectionalModes(t *testing.T) {
	table, err := NewTableWithCustom("seed-custom", "up_ascii_down_entropy", "xpxvvpvv")
	if err != nil {
		t.Fatalf("failed to build directional table: %v", err)
	}
	if !table.IsASCII || table.layout.name != "ascii" {
		t.Fatalf("expected uplink ascii layout, got %s", table.layout.name)
	}
	if peer := table.OppositeDirection(); peer == nil || peer == table {
		t.Fatalf("expected distinct downlink table")
	} else if peer.IsASCII || peer.layout.name == "ascii" {
		t.Fatalf("expected entropy/custom downlink layout, got %s", peer.layout.name)
	}

	table, err = NewTableWithCustom("seed-custom", "up_entropy_down_ascii", "xpxvvpvv")
	if err != nil {
		t.Fatalf("failed to build reverse directional table: %v", err)
	}
	if table.IsASCII || table.layout.name == "ascii" {
		t.Fatalf("expected entropy/custom uplink layout, got %s", table.layout.name)
	}
	if peer := table.OppositeDirection(); peer == nil || peer == table {
		t.Fatalf("expected distinct ascii downlink table")
	} else if !peer.IsASCII || peer.layout.name != "ascii" {
		t.Fatalf("expected ascii downlink layout, got %s", peer.layout.name)
	}

	alt, err := NewTableWithCustom("seed-custom", "up_ascii_down_entropy", "vxpvxvvp")
	if err != nil {
		t.Fatalf("failed to build alternate directional table: %v", err)
	}
	if table.Hint() == alt.Hint() {
		t.Fatalf("directional entropy downlink hint should change with custom pattern")
	}
}

func TestCustomLayoutConnRoundTrip(t *testing.T) {
	table, err := NewTableWithCustom("roundtrip", "prefer_entropy", "xpxvvpvv")
	if err != nil {
		t.Fatalf("table creation failed: %v", err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	writer := NewConn(c1, table, 0, 0, false)
	reader := NewConn(c2, table, 0, 0, false)

	payload := bytes.Repeat([]byte("sudoku-custom-layout"), 2048)
	done := make(chan error, 1)
	go func() {
		_, err := writer.Write(payload)
		done <- err
	}()

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if !bytes.Equal(payload, buf) {
		t.Fatalf("payload mismatch")
	}
}

func TestCustomLayoutPackedRoundTrip(t *testing.T) {
	table, err := NewTableWithCustom("packed-roundtrip", "prefer_entropy", "xpxvvpvv")
	if err != nil {
		t.Fatalf("table creation failed: %v", err)
	}

	c1, c2 := net.Pipe()
	defer c2.Close()

	writer := NewPackedConn(c1, table, 0, 0)
	reader := NewPackedConn(c2, table, 0, 0)

	payload := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x01}, 8192)
	done := make(chan error, 1)
	go func() {
		defer c1.Close()

		if _, err := writer.Write(payload); err != nil {
			done <- err
			return
		}
		done <- writer.Flush()
	}()

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatalf("drain failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("write/flush failed: %v", err)
	}
	if !bytes.Equal(payload, buf) {
		t.Fatalf("payload mismatch")
	}
}

func TestCustomLayoutInvalidPatterns(t *testing.T) {
	if _, err := NewTableWithCustom("seed", "prefer_entropy", "xxxxvvvv"); err == nil {
		t.Fatalf("expected error for invalid pattern")
	}
	if _, err := NewTableWithCustom("seed", "badmode", "xpxvvpvv"); err == nil {
		t.Fatalf("expected error for invalid ascii mode")
	}
	if _, err := NewTableWithCustom("seed", "up_ascii_down_bad", "xpxvvpvv"); err == nil {
		t.Fatalf("expected error for invalid directional ascii mode")
	}
}

func TestCustomLayoutPackedStress(t *testing.T) {
	table, err := NewTableWithCustom("stress-key", "prefer_entropy", "vxpvxvvp")
	if err != nil {
		t.Fatalf("table creation failed: %v", err)
	}

	c1, c2 := net.Pipe()
	defer c2.Close()

	writer := NewPackedConn(c1, table, 2, 4)
	reader := NewPackedConn(c2, table, 2, 4)

	payload := bytes.Repeat([]byte{0xFF, 0x00, 0x7F, 0x11, 0x22}, 20000)
	done := make(chan error, 1)
	go func() {
		defer c1.Close()

		if _, err := writer.Write(payload); err != nil {
			done <- err
			return
		}
		done <- writer.Flush()
	}()

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatalf("drain failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("write/flush failed: %v", err)
	}
	if !bytes.Equal(payload, buf) {
		t.Fatalf("stress payload mismatch")
	}
}
