package outbound

import (
	"encoding/binary"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
)

// buildTLSHello returns a TLS handshake record header followed by payloadLen
// zero bytes. Total length = payloadLen + 5.
func buildTLSHello(payloadLen int) []byte {
	buf := make([]byte, 5+payloadLen)
	buf[0] = 0x16
	buf[1] = 0x03
	buf[2] = 0x01
	binary.BigEndian.PutUint16(buf[3:5], uint16(payloadLen))
	return buf
}

func TestFragment_Parse(t *testing.T) {
	t.Run("defaults to tlshello", func(t *testing.T) {
		cfg, err := parseFragmentSettings(FinalMaskLayerSettings{})
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.tlshello {
			t.Errorf("tlshello = false, want true")
		}
	})

	t.Run("explicit tlshello", func(t *testing.T) {
		cfg, err := parseFragmentSettings(FinalMaskLayerSettings{Packets: "tlshello"})
		if err != nil || !cfg.tlshello {
			t.Fatalf("err=%v tlshello=%v", err, cfg.tlshello)
		}
	})

	t.Run("packets range 1-3", func(t *testing.T) {
		cfg, err := parseFragmentSettings(FinalMaskLayerSettings{Packets: "1-3"})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.tlshello {
			t.Errorf("tlshello = true, want false")
		}
		if cfg.writeRange.Start() != 1 || cfg.writeRange.End() != 3 {
			t.Errorf("writeRange = %v, want {1,3}", cfg.writeRange)
		}
	})

	t.Run("packets range must start at 1", func(t *testing.T) {
		if _, err := parseFragmentSettings(FinalMaskLayerSettings{Packets: "0-3"}); err == nil {
			t.Fatal("expected error for range starting at 0")
		}
	})

	t.Run("packets invalid range", func(t *testing.T) {
		if _, err := parseFragmentSettings(FinalMaskLayerSettings{Packets: "abc"}); err == nil {
			t.Fatal("expected error for invalid range")
		}
	})

	t.Run("lengths array parsed", func(t *testing.T) {
		cfg, err := parseFragmentSettings(FinalMaskLayerSettings{
			Lengths: []string{"3-5", "10-20"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.lengths) != 2 {
			t.Fatalf("got %d lengths, want 2", len(cfg.lengths))
		}
		if cfg.lengths[0].Start() != 3 || cfg.lengths[0].End() != 5 {
			t.Errorf("lengths[0] = %v, want {3,5}", cfg.lengths[0])
		}
		if cfg.lengths[1].Start() != 10 || cfg.lengths[1].End() != 20 {
			t.Errorf("lengths[1] = %v, want {10,20}", cfg.lengths[1])
		}
	})

	t.Run("last length entry must be non-zero", func(t *testing.T) {
		_, err := parseFragmentSettings(FinalMaskLayerSettings{
			Lengths: []string{"10", "0"},
		})
		if err == nil {
			t.Fatal("expected error when last length entry is zero")
		}
	})

	t.Run("delays array parsed", func(t *testing.T) {
		cfg, err := parseFragmentSettings(FinalMaskLayerSettings{Delays: []string{"10", "20"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.delays) != 2 || cfg.delays[0].Start() != 10 || cfg.delays[1].Start() != 20 {
			t.Errorf("delays = %v", cfg.delays)
		}
	})

	t.Run("max-split picks upper bound", func(t *testing.T) {
		cfg, err := parseFragmentSettings(FinalMaskLayerSettings{MaxSplit: "3-6"})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.maxSplit != 6 {
			t.Errorf("maxSplit = %d, want 6", cfg.maxSplit)
		}
	})

	t.Run("max-split invalid", func(t *testing.T) {
		if _, err := parseFragmentSettings(FinalMaskLayerSettings{MaxSplit: "abc"}); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestFragmentConn_TLSHelloFragmentsFirstRecord(t *testing.T) {
	const payloadLen = 100
	data := buildTLSHello(payloadLen) // 105 bytes

	rc := newRecordConn()
	cfg := &fragmentSettings{
		packets:  "tlshello",
		tlshello: true,
		lengths:  []utils.Range[int]{rangeOf(10, 10)},
		delays:   []utils.Range[int]{rangeOf(0, 0)},
	}
	conn := newFragmentConn(rc, cfg)

	n, err := conn.Write(data)
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}

	// 105 bytes / 10 = 10 full + 1 partial of 5 = 11 writes.
	if len(rc.writes) != 11 {
		t.Fatalf("got %d writes, want 11", len(rc.writes))
	}
	if conn.totalToFragment != payloadLen+5 {
		t.Errorf("totalToFragment = %d, want %d", conn.totalToFragment, payloadLen+5)
	}
	if conn.phase != phasePassthrough {
		t.Errorf("phase = %v, want phasePassthrough", conn.phase)
	}
}

func TestFragmentConn_TLSHelloSecondWriteIsPassthrough(t *testing.T) {
	cfg := &fragmentSettings{
		packets: "tlshello", tlshello: true,
		lengths: []utils.Range[int]{rangeOf(10, 10)},
	}
	rc := newRecordConn()
	conn := newFragmentConn(rc, cfg)

	if _, err := conn.Write(buildTLSHello(20)); err != nil {
		t.Fatal(err)
	}
	// 25 bytes / 10 = 2 full + 1 partial of 5 = 3 writes.
	if len(rc.writes) != 3 {
		t.Fatalf("first batch writes = %d, want 3", len(rc.writes))
	}

	more := []byte("after-hello")
	if _, err := conn.Write(more); err != nil {
		t.Fatal(err)
	}
	if len(rc.writes) != 4 {
		t.Fatalf("got %d total writes, want 4", len(rc.writes))
	}
	if string(rc.writes[3]) != string(more) {
		t.Errorf("passthrough mismatch: got %q want %q", rc.writes[3], more)
	}
}

func TestFragmentConn_NonTLSDataIsPassthrough(t *testing.T) {
	cfg := &fragmentSettings{
		packets: "tlshello", tlshello: true,
		lengths: []utils.Range[int]{rangeOf(5, 5)},
	}
	rc := newRecordConn()
	conn := newFragmentConn(rc, cfg)

	// First byte 'G' (0x47) is not a TLS handshake.
	data := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
	if len(rc.writes) != 1 {
		t.Fatalf("got %d writes, want 1 (passthrough)", len(rc.writes))
	}
	if conn.phase != phasePassthrough {
		t.Errorf("phase = %v, want phasePassthrough", conn.phase)
	}
}

func TestFragmentConn_TooShortDataIsPassthrough(t *testing.T) {
	cfg := &fragmentSettings{packets: "tlshello", tlshello: true, lengths: []utils.Range[int]{rangeOf(5, 5)}}
	rc := newRecordConn()
	conn := newFragmentConn(rc, cfg)

	if _, err := conn.Write([]byte{0x16, 0x03, 0x01}); err != nil {
		t.Fatal(err)
	}
	if len(rc.writes) != 1 || conn.phase != phasePassthrough {
		t.Fatalf("got %d writes, phase=%v, want 1 + passthrough", len(rc.writes), conn.phase)
	}
}

func TestFragmentConn_IndexedModeFragmentsSpecifiedWrites(t *testing.T) {
	cfg := &fragmentSettings{
		packets:    "1-2",
		lengths:    []utils.Range[int]{rangeOf(5, 5)},
		writeRange: rangeOf(1, 2),
	}
	rc := newRecordConn()
	conn := newFragmentConn(rc, cfg)

	// Write 1 — fragment.
	if _, err := conn.Write(make([]byte, 12)); err != nil {
		t.Fatal(err)
	}
	// 12 / 5 = 2 full + 1 partial of 2 = 3 writes.
	if len(rc.writes) != 3 {
		t.Fatalf("write 1: got %d writes, want 3", len(rc.writes))
	}
	// Write 2 — fragment.
	if _, err := conn.Write(make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	// 7 / 5 = 1 full + 1 partial of 2 = 2 writes. Total now 5.
	if len(rc.writes) != 5 {
		t.Fatalf("write 2: got %d total writes, want 5", len(rc.writes))
	}
	// Phase switches to passthrough after write 2.
	if conn.phase != phasePassthrough {
		t.Errorf("phase after write 2 = %v, want phasePassthrough", conn.phase)
	}

	// Write 3 — passthrough, single write.
	if _, err := conn.Write([]byte("done")); err != nil {
		t.Fatal(err)
	}
	if len(rc.writes) != 6 {
		t.Fatalf("write 3: got %d total writes, want 6", len(rc.writes))
	}
	if string(rc.writes[5]) != "done" {
		t.Errorf("passthrough payload mismatch: got %q", rc.writes[5])
	}
}

func TestFragmentConn_IndexedModePreRangeWriteIsPassthrough(t *testing.T) {
	cfg := &fragmentSettings{
		packets:    "3-4",
		lengths:    []utils.Range[int]{rangeOf(5, 5)},
		writeRange: rangeOf(3, 4),
	}
	rc := newRecordConn()
	conn := newFragmentConn(rc, cfg)

	// Writes 1 and 2 fall before the range — passthrough.
	if _, err := conn.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if len(rc.writes) != 2 {
		t.Fatalf("pre-range writes: got %d writes, want 2", len(rc.writes))
	}
	// Write 3 enters the range — fragment.
	if _, err := conn.Write(make([]byte, 12)); err != nil {
		t.Fatal(err)
	}
	if len(rc.writes) != 2+3 {
		t.Fatalf("write 3: got %d total writes, want 2+3=5", len(rc.writes))
	}
}

func TestFragmentConn_PerFragmentLengthsArray(t *testing.T) {
	// First fragment uses 3-byte length, second uses 5, third and beyond reuse 5.
	cfg := &fragmentSettings{
		packets: "tlshello", tlshello: true,
		lengths: []utils.Range[int]{rangeOf(3, 3), rangeOf(5, 5)},
	}
	rc := newRecordConn()
	conn := newFragmentConn(rc, cfg)

	data := buildTLSHello(20) // 25 bytes total
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}

	// Expected sizes: 3, 5, 5, 5, 5, 2  → 6 writes.
	wantSizes := []int{3, 5, 5, 5, 5, 2}
	if len(rc.writes) != len(wantSizes) {
		t.Fatalf("got %d writes, want %d", len(rc.writes), len(wantSizes))
	}
	for i, want := range wantSizes {
		if len(rc.writes[i]) != want {
			t.Errorf("write[%d] len = %d, want %d", i, len(rc.writes[i]), want)
		}
	}
}

func TestFragmentConn_IdlePassOnZeroLength(t *testing.T) {
	// lengths: 0 (idle pass), then 10 (productive). delays: 1ms, 1ms.
	// 20-byte payload: pass 0 idle, pass 1 fragments 10 bytes, pass 2 fragments 10 bytes.
	cfg := &fragmentSettings{
		packets: "tlshello", tlshello: true,
		lengths: []utils.Range[int]{rangeOf(0, 0), rangeOf(10, 10)},
		delays:  []utils.Range[int]{rangeOf(1, 1)},
	}
	rc := newRecordConn()
	conn := newFragmentConn(rc, cfg)

	data := buildTLSHello(20) // 25 bytes
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}

	// Idle pass produces no write. Then 2 fragments of 10 bytes + 1 of 5 = 3 writes.
	wantSizes := []int{10, 10, 5}
	if len(rc.writes) != len(wantSizes) {
		t.Fatalf("got %d writes %v, want %d (idle pass produced no write)", len(rc.writes), sizesOf(rc.writes), len(wantSizes))
	}
	for i, want := range wantSizes {
		if len(rc.writes[i]) != want {
			t.Errorf("write[%d] len = %d, want %d", i, len(rc.writes[i]), want)
		}
	}
}

func TestFragmentConn_MaxSplitLimit(t *testing.T) {
	// maxSplit=2 → at most 2 fragments, remaining sent as one chunk.
	cfg := &fragmentSettings{
		packets: "tlshello", tlshello: true,
		lengths:  []utils.Range[int]{rangeOf(5, 5)},
		maxSplit: 2,
	}
	rc := newRecordConn()
	conn := newFragmentConn(rc, cfg)

	data := buildTLSHello(40) // 45 bytes
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}

	// 2 fragments of 5 bytes + remaining 35 as one chunk = 3 writes.
	wantSizes := []int{5, 5, 35}
	if len(rc.writes) != len(wantSizes) {
		t.Fatalf("got %d writes %v, want %d", len(rc.writes), sizesOf(rc.writes), len(wantSizes))
	}
	for i, want := range wantSizes {
		if len(rc.writes[i]) != want {
			t.Errorf("write[%d] len = %d, want %d", i, len(rc.writes[i]), want)
		}
	}
}

func TestFragmentConn_EmptyLengthsIsPassthrough(t *testing.T) {
	// No lengths specified → fragmentSize becomes 0 → send all in one chunk.
	cfg := &fragmentSettings{packets: "tlshello", tlshello: true}
	rc := newRecordConn()
	conn := newFragmentConn(rc, cfg)

	data := buildTLSHello(40)
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
	if len(rc.writes) != 1 {
		t.Fatalf("got %d writes, want 1 (no fragmentation without lengths)", len(rc.writes))
	}
}

// sizesOf is a small helper for clearer test failure messages.
func sizesOf(writes [][]byte) []int {
	out := make([]int, len(writes))
	for i, w := range writes {
		out[i] = len(w)
	}
	return out
}
