// auth.go —— 快路 auth_tag。快路无 ServerHello,客户端发 auth_tag,服务端 ct_eq 比对。
// 对照 Rust crypto.rs:251-280。

package crypto

import "encoding/binary"

// FastAuthKey = DeriveKey(AUTH_KEY_CTX, psk) → k_auth(对照 Rust fast_auth_key,crypto.rs:261-263)。
// PSK 不直接进 MAC,先经域分离派成 k_auth:泄露的 MAC 输入 transcript 无法反推 PSK。
func FastAuthKey(psk Psk) Key {
	return DeriveKey(AuthKeyCtx, psk[:])
}

// FastAuthTag 算快路 auth_tag(32B):
//
//	auth_tag = BLAKE3-MAC(k_auth, FastAuthMsg ‖ exporter ‖ ver ‖ caps_c:BE ‖ max_bw_c:BE)
//
// (对照 Rust fast_auth_tag,crypto.rs:266-280)。**auth_tag 绑客户端声明值**(非协商值):
// 快路无 ServerHello,客户端算 tag 时不知服务端 caps_s / max_bw_s,故只绑 ver/caps_c/max_bw_c,
// 服务端按收到的声明重算比对。完整理由见 Rust crypto.rs:252-256 注释。
//
// exporter 是 TLS exporter(post-handshake,两端字节一致)—— 它同时是会话密钥的 IKM,
// 故 auth_tag 隐式绑定「本次 TLS 会话」(防重放/绑流)。
func FastAuthTag(kAuth Key, exporter Key, ver byte, capsC uint16, maxBwC uint32) [MacLen]byte {
	v := make([]byte, 0, len(FastAuthMsg)+KeyLen+1+2+4)
	v = append(v, FastAuthMsg...)
	v = append(v, exporter[:]...)
	v = append(v, ver)
	v = binary.BigEndian.AppendUint16(v, capsC)
	v = binary.BigEndian.AppendUint32(v, maxBwC)
	return Blake3Mac(kAuth, v)
}
