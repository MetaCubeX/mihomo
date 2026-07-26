package wire

import (
	"bytes"
	"testing"
)

// 对照 Rust frame::build_aad(FrameType::TcpData, 0x1234, 0x5678_9abc) + parse_header round-trip。
func TestFrameHeaderAADRoundTrip(t *testing.T) {
	h := FrameHeader{Type: FrameTCPData, Len: 0x1234, Ctr: 0x56789abc}
	aad := h.BuildAAD()
	// + Rust 真值:type(02) len(12 34) ctr(56 78 9a bc)。
	want := []byte{0x02, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	if !bytes.Equal(aad[:], want) {
		t.Fatalf("got %x want %x", aad[:], want)
	}
	got, err := ParseHeader(aad[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("got %+v want %+v", got, h)
	}
}

// FRAME_HEADER_LEN 必须是 7(type 1 + len 2 + ctr 4;对照 Rust FRAME_HEADER_LEN)。
func TestFrameHeaderLen7(t *testing.T) {
	if FrameHeaderLen != 7 {
		t.Fatalf("FRAME_HEADER_LEN = %d, want 7", FrameHeaderLen)
	}
}

func TestFrameHeaderRejectsShortAndBadType(t *testing.T) {
	if _, err := ParseHeader([]byte{1, 2, 3}); err != ErrFrameTruncated {
		t.Fatalf("want ErrFrameTruncated, got %v", err)
	}
	// 方案 1C:critical 未知(0x0B-0x7F)→ ErrUnknownFrameType(fail-loud);skippable 未知(0x80+)→ 接受(存原始字节,解码侧盲丢)。
	crit := FrameHeader{Type: FrameTCPData, Len: 0, Ctr: 0}.BuildAAD()
	crit[0] = 0x0B // critical 未知
	if _, err := ParseHeader(crit[:]); err != ErrUnknownFrameType {
		t.Fatalf("want ErrUnknownFrameType for 0x0B, got %v", err)
	}
	skip := FrameHeader{Type: FrameTCPData, Len: 0, Ctr: 0}.BuildAAD()
	skip[0] = 0x85 // skippable 未知(0x80+)
	if h, err := ParseHeader(skip[:]); err != nil || byte(h.Type) != 0x85 {
		t.Fatalf("want skippable 0x85 accepted, got type=%#x err=%v", byte(h.Type), err)
	}
}

func TestClassify(t *testing.T) {
	// 已知 → Known;0x80+ 未知 → Skippable;0x00 / 0x0B-0x7F 未知 → Critical(对照 Rust classify)。
	cases := []struct {
		b    byte
		want FrameClass
	}{
		{0x02, FrameKnown}, {0x0A, FrameKnown},
		{0x80, FrameSkippable}, {0xFF, FrameSkippable},
		{0x00, FrameCritical}, {0x0B, FrameCritical}, {0x7F, FrameCritical},
	}
	for _, c := range cases {
		if got := Classify(c.b); got != c.want {
			t.Fatalf("Classify(%#x) = %v, want %v", c.b, got, c.want)
		}
	}
}

// MarshalHeader 与 BuildAAD 字节一致(零 alloc 版)。
func TestMarshalHeaderEqBuildAAD(t *testing.T) {
	h := FrameHeader{Type: FramePing, Len: 0x10, Ctr: 0x20}
	b := make([]byte, FrameHeaderLen)
	h.MarshalHeader(b)
	aad := h.BuildAAD()
	if !bytes.Equal(b, aad[:]) {
		t.Fatalf("MarshalHeader %x != BuildAAD %x", b, aad[:])
	}
}

// MaxPayloadLen = 65535 - 16(tag)= 65519;MaxFrameBodyLen = 65535(对照 Rust frame::MAX_PAYLOAD_LEN/MAX_FRAME_BODY_LEN)。
func TestMaxPayloadLen(t *testing.T) {
	if MaxPayloadLen != 65519 {
		t.Fatalf("MaxPayloadLen = %d, want 65519", MaxPayloadLen)
	}
	if MaxFrameBodyLen != 65535 {
		t.Fatalf("MaxFrameBodyLen = %d, want 65535", MaxFrameBodyLen)
	}
}

// 全帧类型 0x01-0x0A round-trip;0x00 / 0x0B 非法(对照 Rust FrameType::from_u8)。
func TestAllFrameTypes(t *testing.T) {
	for b := byte(0x01); b <= 0x0A; b++ {
		ft, ok := FrameTypeFromByte(b)
		if !ok {
			t.Fatalf("0x%02x should be valid", b)
		}
		if byte(ft) != b {
			t.Fatalf("roundtrip 0x%02x", b)
		}
	}
	if _, ok := FrameTypeFromByte(0x00); ok {
		t.Fatal("0x00 invalid")
	}
	if _, ok := FrameTypeFromByte(0x0B); ok {
		t.Fatal("0x0B invalid")
	}
}
