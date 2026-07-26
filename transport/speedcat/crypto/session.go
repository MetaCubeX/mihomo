// session.go —— 会话密钥派生(伪装路 handshake_secret / 快路 exporter → 四子密钥)
// + 伪装路握手 MAC 输入构造。对照 Rust crypto.rs:191-249。

package crypto

import "encoding/binary"

// KeyDiversifier 会话密钥的 IKM 分离器(RISK 1 结构化守卫;对照 Rust crypto.rs `KeyDiversifier`)。
//
// 强制调用方声明 stream 分离语义:WholeConnection 复现历史字节;StreamDiv(id) 把 id 揉进 IKM
// (StreamDivCtx)再派生 → 跨流 (key,nonce) 天然分离。**今天快路恒 WholeConnection**(NO_INNER_AEAD 不用
// 这些 key);未来给快路加内层 AEAD 时 pooled 流须改 StreamDiv(quic stream-id),须与 Rust 端同步。
type KeyDiversifier struct {
	stream bool
	id     uint64
}

// WholeConnection 整连接一份密钥(identity:不经 StreamDivCtx,与历史逐字节一致)。
var WholeConnection = KeyDiversifier{}

// StreamDiv 按 stream-id 分离(QUIC stream-id 两端对称 → 零额外 wire 字节)。
func StreamDiv(id uint64) KeyDiversifier { return KeyDiversifier{stream: true, id: id} }

// DeriveSessionKeys 从 IKM(伪装路=handshake_secret / 快路=exporter)派生四会话子密钥
// (对照 Rust crypto.rs `derive_session_keys`)。c2s/s2c 方向 + key/nonce 域分离,context 见 crypto.go 常量块。
//
// div 强制声明 stream 分离语义(见 KeyDiversifier):WholeConnection 复现历史字节;StreamDiv(id) 先把 id
// 揉进 IKM 再派生。nonce 取 DeriveKey 输出(32B)的前 12B(Rust nonce12_from;省一次 DeriveKey)。
func DeriveSessionKeys(ikm Key, div KeyDiversifier) SessionKeys {
	eff := ikm
	if div.stream {
		buf := make([]byte, 0, KeyLen+8)
		buf = append(buf, ikm[:]...)
		buf = binary.BigEndian.AppendUint64(buf, div.id)
		eff = DeriveKey(StreamDivCtx, buf)
	}
	return SessionKeys{
		C2SKey:   DeriveKey(C2SKeyCtx, eff[:]),
		S2CKey:   DeriveKey(S2CKeyCtx, eff[:]),
		C2SNonce: nonce12From(DeriveKey(C2SNonceCtx, eff[:])),
		S2CNonce: nonce12From(DeriveKey(S2CNonceCtx, eff[:])),
	}
}

// nonce12From 截 BLAKE3 输出前 12B 作 nonce(对照 Rust nonce12_from,crypto.rs:206-210)。
func nonce12From(b Key) [NonceLen]byte {
	var n [NonceLen]byte
	copy(n[:], b[:NonceLen])
	return n
}

// DisguiseHSInput 构造伪装路握手 MAC 的输入明文(8 字段 = 进 MAC 的全部 transcript 字段)。
// 顺序严格(SSOT),与 Rust disguise_hs_input(crypto.rs:228-249)逐字节一致:
//
//	HS_CTX ‖ ver_min ‖ ver_max ‖ ver_sel ‖ shared[32] ‖ nonce_c[16] ‖ nonce_s[16]
//	         ‖ caps_neg:BE ‖ max_bw_c:BE ‖ max_bw_s:BE
//
// 返回的 []byte 进 Blake3Mac(psk, input) 得 handshake_secret。**方案 1B:ver_min ‖ ver_max(客户端声明范围)
// + ver_sel(服务端选中 v*)全进 MAC → 改范围/改选择都致首帧 AEAD fail = 全下行降级保护。** Rust 逐字节同款。
func DisguiseHSInput(verMin, verMax, verSel byte, shared Key, nonceC, nonceS [HsNonceLen]byte, capsNeg uint16, maxBwC, maxBwS uint32) []byte {
	v := make([]byte, 0, len(HSCtx)+3+KeyLen+2*HsNonceLen+2+8)
	v = append(v, HSCtx...)
	v = append(v, verMin, verMax, verSel)
	v = append(v, shared[:]...)
	v = append(v, nonceC[:]...)
	v = append(v, nonceS[:]...)
	v = binary.BigEndian.AppendUint16(v, capsNeg)
	v = binary.BigEndian.AppendUint32(v, maxBwC)
	v = binary.BigEndian.AppendUint32(v, maxBwS)
	return v
}
