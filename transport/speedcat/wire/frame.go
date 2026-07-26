package wire

import (
	"encoding/binary"
	"errors"
)

// FrameHeaderLen = type(1) + len(2) + ctr(4) = 7 字节(对照 Rust frame::FRAME_HEADER_LEN)。
const FrameHeaderLen = 7

// AEADTagLen = ChaCha20-Poly1305 tag = 16 字节(/;对照 Rust crypto::TAG_LEN)。
const AEADTagLen = 16

// MaxPayloadLen:AEAD 路 len=payload+tag 须 ≤ u16::MAX(65535)→ payload ≤ 65519;快路 len=payload ≤ 65519(对照 Rust frame::MAX_PAYLOAD_LEN)。
const MaxPayloadLen = 65535 - AEADTagLen // = 65519

// MaxFrameBodyLen:帧头后最大字节数(body 并集上限)= 65535 = u16::MAX(对照 Rust frame::MAX_FRAME_BODY_LEN)。
const MaxFrameBodyLen = MaxPayloadLen + AEADTagLen // = 65535

// ErrFrameTruncated 帧 < FrameHeaderLen(parse_header 拒绝)。
var ErrFrameTruncated = errors.New("speedcat/wire: frame header truncated")

// FrameHeader —— stream 帧头:[type:u8][len:u16][ctr:u32],大端。
//
// Len:AEAD 路 = ciphertext+tag(payload+TAG);NO_INNER_AEAD(快路)= payload(无 tag)。
// Ctr:帧计数器,明文传输,接收方用它构造 nonce(base_nonce XOR be_bytes(ctr))。篡改 ctr → nonce 错 → AEAD 解密失败 → 丢帧。
type FrameHeader struct {
	Type FrameType
	Len  uint16
	Ctr  uint32
}

// BuildAAD 构造 AAD = [type][len:BE][ctr:BE](7 字节)。type/len/ctr 全认证(纳入 AEAD AAD,防被改型/改长/改序)。
// 对照 Rust frame::build_aad。
func (h FrameHeader) BuildAAD() [FrameHeaderLen]byte {
	var a [FrameHeaderLen]byte
	a[0] = byte(h.Type)
	binary.BigEndian.PutUint16(a[1:3], h.Len)
	binary.BigEndian.PutUint32(a[3:7], h.Ctr)
	return a
}

// MarshalHeader 把帧头写入 b 的前 7 字节(对照 Rust build_aad;与 BuildAAD 字节一致,免 alloc 版)。
func (h FrameHeader) MarshalHeader(b []byte) {
	b[0] = byte(h.Type)
	binary.BigEndian.PutUint16(b[1:3], h.Len)
	binary.BigEndian.PutUint32(b[3:7], h.Ctr)
}

// ParseHeader 从 b 前 7 字节解析帧头(对照 Rust frame::parse_header)。未知 type → ErrUnknownFrameType;短 → ErrFrameTruncated。
func ParseHeader(b []byte) (FrameHeader, error) {
	if len(b) < FrameHeaderLen {
		return FrameHeader{}, ErrFrameTruncated
	}
	ft, ok := FrameTypeFromByte(b[0])
	if !ok {
		return FrameHeader{}, ErrUnknownFrameType
	}
	return FrameHeader{
		Type: ft,
		Len:  binary.BigEndian.Uint16(b[1:3]),
		Ctr:  binary.BigEndian.Uint32(b[3:7]),
	}, nil
}
