// Package client 实现 speedcat 协议客户端(L4 A2 五层 proto 库第 5 层):
// 在 L2 transport.Conn + L3 handshake.Session 之上做 **relay / SOCKS5 入口 / UDP 隧道**,产出可独立
// 跑的 SOCKS5 binary(经 Rust server 代理 TCP+UDP; 阶段一完成定义:无需 fork mihomo)。
//
// # 本文件:SessionTx / SessionRx —— 会话加解密半部(镜像 Rust session.rs:17-31,126-259,逐字节)
//
// 握手产出 [handshake.Session](密钥 + caps + max_bw);relay 需加密/解密两向并发,不能共享可变状态,
// 故拆成 [SessionTx](发:ctr 单调)与 [SessionRx](收:重放滑窗 highest)两半 —— 两半无共享可变状态,
// 可各持一引用并发跑(relay pump 双 goroutine)。对照 Rust SessionTx/SessionRx(session.rs)。
//
// # 加密语义
//
// 每帧独立 AEAD + 单调 ctr;重放检查**在 AEAD 成功之后**。两路分支:
//   - **快路**(NoInnerAEAD,exporter 取到):省内层 AEAD,完整性交 TLS record。帧 = [type][len=payload][ctr][plaintext],无 tag。
//   - **伪装路**(NoInnerAEAD=false,exporter 不可取):双层 AEAD。帧 = [type][len=payload+tag][ctr][ciphertext][tag:16]。
//
// # 冷热路径
//
// relay 是热路径(per-packet AEAD + 帧编解码)。本 MVP per-call frame(先正确,每帧各 alloc out)——
// 批量合帧 / 零拷贝留收尾(对齐 Rust ③ issue #1;Go adapter 非 splice 热路径目标,先正确后优化)。
// **AEAD seal/open 内禁日志**(每包日志 5G→1G 塌)。**panic-free**(被 mihomo import 的库:
// AEAD/ctr 错返 error 不 panic,对 Go 库的等价约束)。
package client

import (
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/mihomo/transport/speedcat/handshake"
	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// 会话加解密错误(对照 Rust Error::Wire / Error::Replay / Error::Aead)。
var (
	// ErrPayloadTooLong payload > MaxPayloadLen(对照 Rust SessionTx::advance_ctr Wire)。
	ErrPayloadTooLong = errors.New("client/session: payload > MaxPayloadLen")
	// ErrCtrExhaustion tx ctr 接近耗尽(> 0xF000_0000;对照 Rust advance_ctr 兜底)。
	ErrCtrExhaustion = errors.New("client/session: tx ctr 近耗尽,须重连")
	// ErrFrameTruncated 帧头/body 截断(对照 Rust decrypt_frame_view)。
	ErrFrameTruncated = errors.New("client/session: 帧头/body 截断")
	// ErrReplay 重放(ctr <= highest,AEAD 成功后检查;对照 Rust SessionRx::decrypt_frame_view)。
	ErrReplay = errors.New("client/session: 重放(ctr <= highest)")
	// ErrAEAD AEAD 解密失败(篡改 / 错密钥;对照 Rust Error::Aead)。
	ErrAEAD = errors.New("client/session: AEAD 解密失败")
	// ErrInvalidFrameHeader 帧头畸形(未知 type 等;parse_header 拒)。
	ErrInvalidFrameHeader = errors.New("client/session: 帧头畸形")
)

// ctr 耗尽兜底阈值(对照 Rust 0xF000_0000)。ctr > 此值 → ErrCtrExhaustion(防 nonce 空间耗尽)。
const ctrExhaustionBound uint32 = 0xF000_0000

// SessionTx 发送半部:加密向密钥 + nonce base + 单调 ctr(对照 Rust SessionTx,session.rs:17-22)。
type SessionTx struct {
	key         crypto.Key
	nonceBase   [crypto.NonceLen]byte // BuildNonce 的 base(低 4B 随 ctr XOR)
	ctr         uint32                // 单调帧计数器;首帧(TCPConnect/UDPAssociate)占 0
	noInnerAEAD bool                  // 快路标志(从 Caps.NoInnerAEAD() 派生,单一真相源)
	padding     bool                  // PADDING 塑形(从 Caps.Padding() 派生,对照 Rust SessionTx.padding;ADR-016)
}

// SessionRx 接收半部:解密向密钥 + nonce base + 重放滑窗(highest 已见 ctr;对照 Rust SessionRx)。
type SessionRx struct {
	key         crypto.Key
	nonceBase   [crypto.NonceLen]byte
	highest     uint32 // 仅 hasHighest 为真时有效
	hasHighest  bool   // 是否已见任何帧(首帧前为 false)
	noInnerAEAD bool
}

// NoInnerAEAD 快路标志(relay pump 据此分支;对照 Rust SessionTx::no_inner_aead)。
func (tx *SessionTx) NoInnerAEAD() bool { return tx.noInnerAEAD }

// Padding 报告是否协商 PADDING 塑形(对照 Rust SessionTx::padding,ADR-016)。pumpEncodeFast 据此
// 注入 PADDING 帧(快路 + caps PADDING);decode 两侧无条件消费(不门控)。
func (tx *SessionTx) Padding() bool { return tx.padding }

// NoInnerAEAD 快路标志(对照 Rust SessionRx::no_inner_aead)。
func (rx *SessionRx) NoInnerAEAD() bool { return rx.noInnerAEAD }

// NewClientHalves 从握手成果拆出 client 侧 tx/rx 两半(对照 Rust Session::new(is_client=true) + into_halves)。
// **方向语义(client 侧):** tx = C2SKey/C2SNonce(发向 server);rx = S2CKey/S2CNonce(收自 server)。
// NoInnerAEAD 从 Caps.NoInnerAEAD() 派生(单一真相源:快路 force 置位 / 伪装路 force 清位,见 handshake)。
func NewClientHalves(s *handshake.Session) (SessionTx, SessionRx) {
	noInner := s.Caps.NoInnerAEAD()
	pad := s.Caps.Padding() // ADR-016:PADDING 塑形(快路 + caps PADDING → pumpEncodeFast 注 PADDING)
	return SessionTx{
			key:         s.Keys.C2SKey,
			nonceBase:   s.Keys.C2SNonce,
			ctr:         0,
			noInnerAEAD: noInner,
			padding:     pad,
		},
		SessionRx{
			key:         s.Keys.S2CKey,
			nonceBase:   s.Keys.S2CNonce,
			hasHighest:  false,
			noInnerAEAD: noInner,
		}
}

// advanceCtr 推进 ctr + 超长/耗尽校验,返回本轮 ctr(对照 Rust SessionTx::advance_ctr,
// 单一真源 —— EncryptFrameInto 与未来批量封帧共用)。超长 → ErrPayloadTooLong;ctr 近耗尽 → ErrCtrExhaustion。
func (tx *SessionTx) advanceCtr(payloadLen int) (uint32, error) {
	if payloadLen > wire.MaxPayloadLen {
		return 0, fmt.Errorf("%w: %d > %d", ErrPayloadTooLong, payloadLen, wire.MaxPayloadLen)
	}
	ctr := tx.ctr
	if ctr > ctrExhaustionBound {
		return 0, ErrCtrExhaustion
	}
	tx.ctr++
	return ctr, nil
}

// EncryptFrameInto 加密一帧追加进 out(调用方复用 buffer;对照 Rust SessionTx::encrypt_frame_into)。
// out 不清空 —— 追加(MVP relay pump 每 goroutine 独立 out;首帧前 out 已 reset)。返回本轮写出的字节数。
//
// 快路:[AAD(7B)|plaintext];伪装路:[AAD(7B)|ciphertext|tag(16B)](len = payload+tag,AAD 在加密前定)。
func (tx *SessionTx) EncryptFrameInto(ftype wire.FrameType, payload []byte, out *[]byte) (int, error) {
	ctr, err := tx.advanceCtr(len(payload))
	if err != nil {
		return 0, err
	}
	nonce := crypto.BuildNonce(tx.nonceBase, ctr)
	hdr := wire.FrameHeader{Type: ftype, Ctr: ctr}
	if tx.noInnerAEAD {
		// 快路:len == payload 长度(无 tag);AAD = [type][len][ctr]。
		hdr.Len = uint16(len(payload))
		var aad [wire.FrameHeaderLen]byte
		hdr.MarshalHeader(aad[:])
		*out = append(*out, aad[:]...)
		*out = append(*out, payload...)
		return wire.FrameHeaderLen + len(payload), nil
	}
	// 伪装路:len = ciphertext+tag = payload + TagLen(AEAD 输出长度);AAD 须在加密前定。
	hdr.Len = uint16(len(payload) + crypto.TagLen)
	var aad [wire.FrameHeaderLen]byte
	hdr.MarshalHeader(aad[:])
	ct, err := crypto.AEADEncrypt(tx.key, nonce, payload, aad[:])
	if err != nil {
		return 0, err
	}
	*out = append(*out, aad[:]...)
	*out = append(*out, ct...)
	return wire.FrameHeaderLen + len(ct), nil
}

// sealFrameHeaderFast 快路帧头就地写(L4 收尾 B,对照 Rust SessionTx::seal_frame_header_fast)。
// 供 pumpEncodeFast 头区直写:body 已直读进 batch 头后位置,头写头区 → 免 EncryptFrameInto 的 buf→out memcpy
// (零拷贝,③(c))。快路 Len = payloadLen(无 tag);ctr 单一真源 advanceCtr。dst 须 ≥ FrameHeaderLen
// (调用方保证:pumpEncodeFast 传 batch[n:n+FrameHeaderLen])。
func (tx *SessionTx) sealFrameHeaderFast(ftype wire.FrameType, payloadLen int, dst []byte) error {
	ctr, err := tx.advanceCtr(payloadLen)
	if err != nil {
		return err
	}
	wire.FrameHeader{Type: ftype, Len: uint16(payloadLen), Ctr: ctr}.MarshalHeader(dst)
	return nil
}

// DecryptFrame 解密一帧 → (ftype, payload)(对照 Rust SessionRx::decrypt_frame_view)。
// hdr = 已解析的帧头(ReadFrame 产出,免二次 parse);body = 帧头后已读入的字节(须 ≥ Len 声明长度,
// 多余尾部忽略)。out 复用 buffer(伪装路明文写进 *out;调用方持 out 复用)。
//
// 重放检查在 AEAD 成功之后:stream 保序 → ctr 须严格递增,hasHighest && ctr <= highest → ErrReplay。
// 快路零拷贝(payload == body 切片);伪装路明文写进 out 返回 out 的切片。
func (rx *SessionRx) DecryptFrame(hdr wire.FrameHeader, body []byte, out *[]byte) (wire.FrameType, []byte, error) {
	bodyLen := int(hdr.Len)
	if len(body) < bodyLen {
		return 0, nil, fmt.Errorf("%w: body %d < len %d", ErrFrameTruncated, len(body), bodyLen)
	}
	body = body[:bodyLen] // 只取声明的 body 长度(尾部多余字节忽略,对照 Rust)。

	nonce := crypto.BuildNonce(rx.nonceBase, hdr.Ctr)
	var payload []byte
	if rx.noInnerAEAD {
		// 快路零拷贝:payload == body(明文)。
		payload = body
	} else {
		var aad [wire.FrameHeaderLen]byte
		hdr.MarshalHeader(aad[:])
		pt, err := crypto.AEADDecrypt(rx.key, nonce, body, aad[:])
		if err != nil {
			return 0, nil, fmt.Errorf("%w: %v", ErrAEAD, err)
		}
		*out = append((*out)[:0], pt...)
		payload = *out
	}

	// 重放检查(AEAD 成功后):stream 保序 → ctr 严格递增(对照 Rust match highest)。
	if rx.hasHighest && hdr.Ctr <= rx.highest {
		return 0, nil, ErrReplay
	}
	rx.highest = hdr.Ctr
	rx.hasHighest = true
	return hdr.Type, payload, nil
}
