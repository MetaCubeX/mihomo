package wire

import (
	"bytes"
	"testing"
)

// 对照 Rust frame::build_aad(FrameType::TcpData, 0x1234, 0x5678_9abc) + parse_header round-trip。
func TestFrameHeaderAADRoundTrip(t *testing.T) {
	h := FrameHeader{Type: FrameTCPData, Len: 0x1234, Ctr: 0x56789abc}
	aad := h.BuildAAD()
	// 02 §3 + Rust 真值:type(02) len(12 34) ctr(56 78 9a bc)。
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

// FRAME_HEADER_LEN 必须是 7(type 1 + len 2 + ctr 4;02 §3;对照 Rust FRAME_HEADER_LEN)。
func TestFrameHeaderLen7(t *testing.T) {
	if FrameHeaderLen != 7 {
		t.Fatalf("FRAME_HEADER_LEN = %d, want 7", FrameHeaderLen)
	}
}

func TestFrameHeaderRejectsShortAndBadType(t *testing.T) {
	if _, err := ParseHeader([]byte{1, 2, 3}); err != ErrFrameTruncated {
		t.Fatalf("want ErrFrameTruncated, got %v", err)
	}
	bad := FrameHeader{Type: FrameTCPData, Len: 0, Ctr: 0}.BuildAAD()
	bad[0] = 0xff // 未知类型
	if _, err := ParseHeader(bad[:]); err != ErrUnknownFrameType {
		t.Fatalf("want ErrUnknownFrameType, got %v", err)
	}
}

// MarshalHeader 与 BuildAAD 字节一致(零 alloc 版,02 §3)。
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
