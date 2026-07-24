// session.go —— 会话密钥派生(伪装路 handshake_secret / 快路 exporter → 四子密钥)
// + 伪装路握手 MAC 输入构造。对照 Rust crypto.rs:191-249。

package crypto

import "encoding/binary"

// DeriveSessionKeys 从 IKM(伪装路=handshake_secret / 快路=exporter)派生四会话子密钥
// (对照 Rust crypto.rs:213-220)。c2s/s2c 方向 + key/nonce 域分离,context 见 crypto.go 常量块。
//
// nonce 取 DeriveKey 输出(32B)的前 12B(Rust nonce12_from):BLAKE3 派生 32B 但 ChaCha20-Poly1305
// nonce 仅 12B,截前 12B(不另派,省一次 DeriveKey;Rust 同此)。
func DeriveSessionKeys(ikm Key) SessionKeys {
	return SessionKeys{
		C2SKey:   DeriveKey(C2SKeyCtx, ikm[:]),
		S2CKey:   DeriveKey(S2CKeyCtx, ikm[:]),
		C2SNonce: nonce12From(DeriveKey(C2SNonceCtx, ikm[:])),
		S2CNonce: nonce12From(DeriveKey(S2CNonceCtx, ikm[:])),
	}
}

// nonce12From 截 BLAKE3 输出前 12B 作 nonce(对照 Rust nonce12_from,crypto.rs:206-210)。
func nonce12From(b Key) [NonceLen]byte {
	var n [NonceLen]byte
	copy(n[:], b[:NonceLen])
	return n
}

// DisguiseHSInput 构造伪装路握手 MAC 的输入明文(8 字段 = 进 MAC 的全部 transcript 字段)。
// 顺序严格(03 §3 SSOT),与 Rust disguise_hs_input(crypto.rs:228-249)逐字节一致:
//
//	HS_CTX ‖ ver_lo ‖ ver_hi ‖ shared[32] ‖ nonce_c[16] ‖ nonce_s[16]
//	         ‖ caps_neg:BE ‖ max_bw_c:BE ‖ max_bw_s:BE
//
// 返回的 []byte 进 Blake3Mac(psk, input) 得 handshake_secret(03 §3)。ver_lo/ver_hi 平铺:
// Rust 同款(预留版本区间协商,P1 阶段 lo==hi==PROTOCOL_VERSION)。
func DisguiseHSInput(verLo, verHi byte, shared Key, nonceC, nonceS [HsNonceLen]byte, capsNeg uint16, maxBwC, maxBwS uint32) []byte {
	v := make([]byte, 0, len(HSCtx)+2+KeyLen+2*HsNonceLen+2+8)
	v = append(v, HSCtx...)
	v = append(v, verLo, verHi)
	v = append(v, shared[:]...)
	v = append(v, nonceC[:]...)
	v = append(v, nonceS[:]...)
	v = binary.BigEndian.AppendUint16(v, capsNeg)
	v = binary.BigEndian.AppendUint32(v, maxBwC)
	v = binary.BigEndian.AppendUint32(v, maxBwS)
	return v
}
