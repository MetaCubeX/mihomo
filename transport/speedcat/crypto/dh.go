// dh.go —— X25519 临时 DH 密钥对(伪装路 eph DH)+ 握手随机 nonce。
// 对照 Rust crypto.rs:55-94(DhKeypair)+ :143-146(random_hs_nonce)。
//
// **仅伪装路用**(exporter=None 时跑 eph DH 换握手密钥;快路 exporter=Some 不经此)。
// speedcat 用 X25519(RFC 7748),与 WireGuard / Noise / TLS 1.3 同族(「不发明新密码学」)。
// 每会话新生成(EphemeralSecret 语义)→ 前向保密:PSK 泄露也解不开历史会话(eph 是短期的)。
//
// **安全铁律(line 91):DH 输出全零必须拒。** 这里有两道互补防线(对照 Rust crypto.rs:75-89):
//  1. `curve25519.X25519` v0.54.0 内部委托 crypto/ecdh(curve25519.go:77-93),**计算期**即拒低序点
//     —— 库自述(curve25519.go:25-26):「32B 输入下,error 当且仅当输出会全零」。与 x25519_dalek
//     不同(dalek 先算出可能的全零再 `was_contributory()` 查),殊途同归都拦非贡献性 DH。本端把库错
//     **规约为 `ErrDhNonContributory`**(对齐 Rust 单一错误类型)。**实证**:dh_test.go
//     TestDH_LowOrderPointsRejected 用 x/crypto 同款 7 个 libsodium 低序点钉死库拒绝行为。
//  2. 防御性 **二次全零校验**(crypto.rs:80-86 同款):即便库放过,显式查 32B 全零 → ErrDhNonContributory。
//
// 漏 = 小子群/无效公钥攻击口子(恶意公钥使 DH 输出可预测 → 攻击者算出会话密钥)。对照 WireGuard
// `noise-helpers.go:100`(精读)。

package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// DhKeypair X25519 临时密钥对(对照 Rust DhKeypair,crypto.rs:58-62)。secret 留本端不外传,
// public 发给对端(ClientHello eph_c / ServerHello eph_s)。值类型:跨 goroutine 复制零共享。
type DhKeypair struct {
	secret [KeyLen]byte // 本端 X25519 私钥(随机 32B;X25519 内部 clamp,无需调用方处理)
	public [KeyLen]byte // 对应公钥(= X25519(secret, Basepoint),确定性派生)
}

// NewDhKeypair 生成新 X25519 临时密钥对(对照 Rust DhKeypair::generate,crypto.rs:64-68)。
// secret 取 crypto/rand 32B(OS CSPRNG);public = X25519(secret, Basepoint)。curve25519.X25519
// 内部 clamp scalar(清低 3 位、置高位),与 x25519_dalek 一致 → 两端公钥/共享字节互通。
//
// **返 error 不 panic**(review follow-up):本包会被 mihomo(长跑宿主代理)import,panic 会 kill
// 整个进程而非断一条连接 —— 库代码不替宿主做 abort 决策。rand.Read 失败仅 OS 熵池异常(近不可达),
// 此时返 error 让调用方按连接级错误处理。Go 构造器惯用 New 前缀(对齐 Rust DhKeypair::generate 语义)。
func NewDhKeypair() (DhKeypair, error) {
	var kp DhKeypair
	// Read 永不返短读(crypto/rand 契约);失败仅 OS 熵池异常 → 返 error(库不 panic,见上)。
	if _, err := rand.Read(kp.secret[:]); err != nil {
		return DhKeypair{}, fmt.Errorf("crypto: rand.Read(dh secret) 失败: %w", err)
	}
	pub, err := curve25519.X25519(kp.secret[:], curve25519.Basepoint)
	if err != nil {
		// 不可达:32B secret + 标准 Basepoint,scalarmult 无失败路径;包成 error 与上同款(库不 panic)。
		return DhKeypair{}, fmt.Errorf("crypto: X25519(secret, Basepoint) 失败(不可达): %w", err)
	}
	copy(kp.public[:], pub)
	return kp, nil
}

// PublicBytes 返回公钥 32B(对照 Rust public_bytes,crypto.rs:70-72)。发进 ClientHello/ServerHello。
func (kp DhKeypair) PublicBytes() [KeyLen]byte { return kp.public }

// DH 算与对端公钥的共享密钥(对照 Rust diffie_hellman,crypto.rs:75-88)。
//
//	shared = X25519(self.secret, peer)
//
// 返回前**校验全零**(line 91):全零 → ErrDhNonContributory(拒小子群攻击)。
// 消费 kp.secret(值拷贝进来,原 kp 仍可用——Go 值语义,无 move 语义,与 Rust self-by-value 不同)。
func (kp DhKeypair) DH(peer [KeyLen]byte) (Key, error) {
	shared, err := curve25519.X25519(kp.secret[:], peer[:])
	if err != nil {
		// 库计算期拒低序点(low order point)→ 规约为 ErrDhNonContributory(line 91;对齐 Rust
		// Error::DhNonContributory:was_contributory=false 或全零都归此)。库自述(curve25519.go:25-26):
		// 32B 输入下,error 当且仅当输出会全零 —— 即低序/无效公钥。实证见 TestDH_LowOrderPointsRejected。
		return Key{}, ErrDhNonContributory
	}
	// 防御性二次全零校验(防小子群/无效公钥攻击, line 91):即便库放过,显式查 32B 全零。
	// 对照 Rust was_contributory() + 二次全零(crypto.rs:80-86);belt-and-suspenders。
	var allZero bool
	{
		var z byte
		for _, b := range shared {
			z |= b
		}
		allZero = z == 0
	}
	if allZero {
		return Key{}, ErrDhNonContributory
	}
	var k Key
	copy(k[:], shared)
	return k, nil
}

// RandomHSNonce 生成 16B 握手随机 nonce(对照 Rust random_hs_nonce,crypto.rs:143-146)。
// 进 ClientHello nonce_c / ServerHello nonce_s;每会话新生 → 绑定本次握手(防重放/域分离)。
//
// **返 error 不 panic**(review follow-up,同 NewDhKeypair 理由:库会被宿主 import,不替宿主 abort)。
func RandomHSNonce() ([HsNonceLen]byte, error) {
	var n [HsNonceLen]byte
	if _, err := rand.Read(n[:]); err != nil {
		return [HsNonceLen]byte{}, fmt.Errorf("crypto: rand.Read(hs nonce) 失败: %w", err)
	}
	return n, nil
}
