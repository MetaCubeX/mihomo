// frame.go —— stream 帧读写(7B 头 + body)+ UDP 帧体编解码(镜像 Rust frame 读写 + udp.rs:57-113)。
//
// ReadFrame/WriteFrame 是 relay / UDP 流隧道臂的帧边界原语:大端 7B 头 → 按 Len 读 body(对照 Rust
// relay pump 读首字节区分干净 EOF / 中段截断的语义 —— Go 用 io.ReadFull + io.EOF 区分)。
//
// UDP body 两结构:
//   - [EncodeUDPAssociate] / [DecodeUDPAssociate]:UdpAssociate 帧(0x04)体 = [assoc_id:u16][target Addr](建 UDP 关联;两路径共用首帧)。
//   - [EncodeUDPData] / [DecodeUDPData]:UdpData 帧(0x05)体 = [Addr][plen:u16][udp_payload](**仅流内隧道**,复用 Session ctr AEAD;TCP 可靠按序 → 单帧一报文不分片)。
//
// 对照 Rust proto-core/src/udp.rs UdpAssociatePayload / UdpDataPayload(逐字节)。

package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// ErrUDPBodyTruncated UDP 帧体截断(对照 Rust udp.rs decode Wire)。
var ErrUDPBodyTruncated = errors.New("client/frame: udp 帧体截断")

// ReadFrame 从 r 读一帧:7B 头 → ParseHeader → 按 Len 读 body。
// 返回 hdr + body(独立归属调用方 —— 委派 [ReadFrameInto] 时每 call 各一份 buf,body 不别名任何复用 buffer)。
// EOF(干净关闭,读首字节即 EOF)→ io.EOF;中段截断(读了部分但凑不齐)→ io.ErrUnexpectedEOF 或包装错误
// (对照 Rust relay pump 语义)。既有调用方(UDP 流隧道臂 / mirrorEcho)零破坏。
func ReadFrame(r io.Reader) (wire.FrameHeader, []byte, error) {
	var buf []byte
	return ReadFrameInto(r, &buf)
}

// ReadFrameInto 从 r 读一帧,body 复用 bodyBuf(L4 收尾 B,对照 Rust relay 读进复用 buffer;零破坏:cap 不够则重 alloc)。
// 返回 hdr + body(bodyBuf 的切片,Len 恰好)。EOF(干净关闭)→ io.EOF;中段截断 → io.ErrUnexpectedEOF 或包装错误。
//
// bodyBuf 在两次调用间复用:返回的 body 切片别名 *bodyBuf,下次调用覆写 → 调用方须在下次调用前用完 body
// (relay 单帧处理满足此约束;UDP 流隧道臂逐帧读→发→读亦满足)。relay pump(per-pump bodyBuf)+ max AEAD 帧路用之。
func ReadFrameInto(r io.Reader, bodyBuf *[]byte) (wire.FrameHeader, []byte, error) {
	var hdrBuf [wire.FrameHeaderLen]byte
	// io.ReadFull:0 字节 → io.EOF(干净关闭);1..6 字节 → io.ErrUnexpectedEOF(中段截断);≥7 → 满。
	if _, err := io.ReadFull(r, hdrBuf[:]); err != nil {
		return wire.FrameHeader{}, nil, err
	}
	hdr, err := wire.ParseHeader(hdrBuf[:])
	if err != nil {
		return wire.FrameHeader{}, nil, fmt.Errorf("client/frame: %w: %v", ErrInvalidFrameHeader, err)
	}
	bodyLen := int(hdr.Len)
	if cap(*bodyBuf) < bodyLen {
		*bodyBuf = make([]byte, bodyLen)
	} else {
		*bodyBuf = (*bodyBuf)[:bodyLen]
	}
	if _, err := io.ReadFull(r, *bodyBuf); err != nil {
		return wire.FrameHeader{}, nil, err
	}
	return hdr, *bodyBuf, nil
}

// WriteFrame 把已加密的 hdr + body 写入 w(relay/UDP 流隧道臂用;帧字节由 SessionTx 产出)。
func WriteFrame(w io.Writer, hdr wire.FrameHeader, body []byte) error {
	var hdrBuf [wire.FrameHeaderLen]byte
	hdr.MarshalHeader(hdrBuf[:])
	if _, err := w.Write(hdrBuf[:]); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// EncodeUDPAssociate 编码 UdpAssociate(0x04)帧体 = [assoc_id:u16 BE][target Addr](对照 Rust UdpAssociatePayload::encode)。
func EncodeUDPAssociate(assocID uint16, target wire.Addr) ([]byte, error) {
	addr, err := target.MarshalBinary()
	if err != nil {
		return nil, err
	}
	v := make([]byte, 0, 2+len(addr))
	v = binary.BigEndian.AppendUint16(v, assocID)
	v = append(v, addr...)
	return v, nil
}

// DecodeUDPAssociate 解码 UdpAssociate 帧体 → (assocID, target)(对照 Rust UdpAssociatePayload::decode)。
func DecodeUDPAssociate(buf []byte) (uint16, wire.Addr, error) {
	if len(buf) < 2 {
		return 0, wire.Addr{}, fmt.Errorf("%w: assoc_id", ErrUDPBodyTruncated)
	}
	assocID := binary.BigEndian.Uint16(buf[0:2])
	target, n, err := wire.DecodeAddr(buf[2:])
	if err != nil {
		return 0, wire.Addr{}, err
	}
	_ = n // 首帧无后续(忽略尾部,对照 Rust rest)。
	return assocID, target, nil
}

// EncodeUDPData 编码 UdpData(0x05)帧体 = [Addr][plen:u16 BE][udp_payload](对照 Rust UdpDataPayload::encode)。
// plen cap u16(UDP 天然 < 64K);超 → 错(fail-loud)。
func EncodeUDPData(addr wire.Addr, data []byte) ([]byte, error) {
	ab, err := addr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(data) > 0xFFFF {
		return nil, fmt.Errorf("client/frame: udp data payload %d > u16", len(data))
	}
	v := make([]byte, 0, len(ab)+2+len(data))
	v = append(v, ab...)
	v = binary.BigEndian.AppendUint16(v, uint16(len(data)))
	v = append(v, data...)
	return v, nil
}

// DecodeUDPData 解码 UdpData 帧体 → (addr, data)(对照 Rust UdpDataPayload::decode)。
func DecodeUDPData(buf []byte) (wire.Addr, []byte, error) {
	addr, n, err := wire.DecodeAddr(buf)
	if err != nil {
		return wire.Addr{}, nil, err
	}
	after := buf[n:] // DecodeAddr 返 consumed 字节数,据此取剩余(plen + payload)。
	if len(after) < 2 {
		return wire.Addr{}, nil, fmt.Errorf("%w: plen", ErrUDPBodyTruncated)
	}
	plen := int(binary.BigEndian.Uint16(after[0:2]))
	if len(after) < 2+plen {
		return wire.Addr{}, nil, fmt.Errorf("%w: payload", ErrUDPBodyTruncated)
	}
	return addr, after[2 : 2+plen], nil
}
