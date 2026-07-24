// errors.go —— crypto 包错误(对照 Rust:解析错误返 String,鉴权错误走 proto-core::Error;
// Go 端用哨兵 error,便于上层(wire/handshake/client)分类处理)。

package crypto

import "errors"

var (
	// ErrPSKLen PSK hex 长度非 64(Rust parse_psk_hex 长度校验,crypto.rs:29-34)。
	ErrPSKLen = errors.New("crypto: psk 须为 64 hex 字符")
	// ErrPSKHex PSK hex 含非法字符(Rust from_str_radix 失败,crypto.rs:38)。
	ErrPSKHex = errors.New("crypto: psk hex 解析失败")
	// ErrDhNonContributory X25519 DH 输出全零(非贡献性,03 §3「DH 输出须校验全零」)。
	// 对照 Rust `Error::DhNonContributory`(crypto.rs:79-88 was_contributory + 二次全零)。
	// 全零 = 小子群/无效公钥攻击征兆,必须拒(防攻击者算出会话密钥)。
	ErrDhNonContributory = errors.New("crypto: dh 输出全零(非贡献性,拒小子群攻击)")
)
