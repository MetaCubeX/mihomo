// aead.go —— ChaCha20-Poly1305 AEAD(IETF,96-bit nonce)+ nonce 构造。
// 对照 Rust crypto.rs:149-177。AEAD 用于伪装路双层(内层)+ datagram(独立 DatagramCipher,见 proto-core datagram.rs)。

package crypto

import "golang.org/x/crypto/chacha20poly1305"

// AEADEncrypt = ChaCha20-Poly1305 seal:ct = AEAD(plaintext, aad),末附 16B tag。
// 返回值布局与 Rust `aead_encrypt`(chacha20poly1305 crate)逐字节一致:ct ‖ tag。
//
// key/nonce 定长 → `chacha20poly1305.New` 的 key 长度错误不可达(返 error 兜底,非热路径)。
// Seal 仅在 nonce 长度错时 panic —— [12]byte 保证,不可达。
func AEADEncrypt(key Key, nonce [NonceLen]byte, plaintext, aad []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(key[:])
	if err != nil {
		// 不可达:[32]byte key 恒满足 New 的 32B 要求。
		return nil, err
	}
	return c.Seal(nil, nonce[:], plaintext, aad), nil
}

// AEADDecrypt = ChaCha20-Poly1305 open:验 tag 通过 → 返明文;tag 不符 → err(鉴权失败/篡改)。
// 这是真实运行期错误路径(对端错密钥/网络篡改),调用方须把 err 当鉴权失败处理(fail-loud)。
func AEADDecrypt(key Key, nonce [NonceLen]byte, ciphertext, aad []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err // 不可达(同上)
	}
	return c.Open(nil, nonce[:], ciphertext, aad)
}

// BuildNonce 构造每包 nonce:`base[12]` 的低 4 字节(bytes 8..12)XOR `ctr` 大端(03 §4.2)。
//
// nonce = base ⊕ {0,0,0,0,0,0,0,0, ctr_be[0], ctr_be[1], ctr_be[2], ctr_be[3]}
// —— base 高 8B 不变,低 4B 随 ctr 单调变化。每方向 base 独立(DeriveKey 派),ctr 单调递增
// → 每 nonce 唯一(防 nonce 重用)。**热路径零 alloc**(值类型拷贝 + 原地 XOR)。
//
// 对照 Rust build_nonce(crypto.rs:164-177)。Rust 有 debug_assert(ctr <= 0xF000_0000)
// 防 nonce 耗尽;Go 端由调用方(SessionTx)守此不变量,此处纯按位 XOR 不额外开销。
func BuildNonce(base [NonceLen]byte, ctr uint32) [NonceLen]byte {
	n := base
	// ctr.to_be_bytes():大端 4 字节,XOR 进 nonce[8:12]。
	n[8] ^= byte(ctr >> 24)
	n[9] ^= byte(ctr >> 16)
	n[10] ^= byte(ctr >> 8)
	n[11] ^= byte(ctr)
	return n
}
