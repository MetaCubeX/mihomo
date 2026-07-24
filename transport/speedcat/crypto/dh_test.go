// dh_test.go —— X25519 DH KAT(RFC 7748 §6.1)+ 对称性 + 低序点拒绝。
//
// X25519 是 RFC 标准,两端(Rust x25519_dalek / Go curve25519)实现同一 spec → 用 RFC 7748
// 通用向量作跨实现 oracle(不必 Rust 印;向量是公开标准)。断言逐字节。
// 复用 crypto_test.go 的 mustHex(hex→[]byte)helper。

package crypto

import (
	"bytes"
	"testing"
)

// hex32 测试辅助:hex → [32]byte(锁 RFC 向量长度;复用 mustHex 做 hex 解码)。
func hex32(t *testing.T, s string) [KeyLen]byte {
	t.Helper()
	b := mustHex(t, s)
	var out [KeyLen]byte
	copy(out[:], b)
	return out
}

// rfc7748 返回 RFC 7748 §6.1 X25519 测试向量(逐字节锁 spec)。
func rfc7748(t *testing.T) (alicePriv, alicePub, bobPriv, bobPub, shared [KeyLen]byte) {
	t.Helper()
	return hex32(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
		hex32(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
		hex32(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
		hex32(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
		hex32(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
}

// TestDH_RFC7748PublicDerivation:Alice 私钥 → 公钥 == RFC 公钥(锁 public 派生 = X25519(secret, Basepoint))。
func TestDH_RFC7748PublicDerivation(t *testing.T) {
	alicePriv, alicePub, _, _, _ := rfc7748(t)
	kp := DhKeypair{secret: alicePriv, public: alicePub} // public 先填 RFC 值
	if got := kp.PublicBytes(); !bytes.Equal(got[:], alicePub[:]) {
		t.Fatalf("PublicBytes != RFC alicePub")
	}
}

// TestDH_RFC7748SharedSecret:Alice×BobPub == Bob×AlicePub == RFC shared(对称 + 逐字节)。
func TestDH_RFC7748SharedSecret(t *testing.T) {
	alicePriv, alicePub, bobPriv, bobPub, shared := rfc7748(t)
	kpA := DhKeypair{secret: alicePriv}
	kpB := DhKeypair{secret: bobPriv}

	sAB, err := kpA.DH(bobPub)
	if err != nil {
		t.Fatalf("A×Bpub: %v", err)
	}
	sBA, err := kpB.DH(alicePub)
	if err != nil {
		t.Fatalf("B×Apub: %v", err)
	}
	if !bytes.Equal(sAB[:], shared[:]) {
		t.Fatalf("A×Bpub != RFC shared")
	}
	if !bytes.Equal(sBA[:], shared[:]) {
		t.Fatalf("B×Apub != RFC shared")
	}
	if !bytes.Equal(sAB[:], sBA[:]) {
		t.Fatalf("DH 不对称")
	}
}

// TestDH_NewDhKeypairRoundTrip:两个随机 keypair 互算 → 共享相等且非全零(锁 NewDhKeypair + DH 端到端)。
func TestDH_NewDhKeypairRoundTrip(t *testing.T) {
	a, err := NewDhKeypair()
	if err != nil {
		t.Fatalf("NewDhKeypair a: %v", err)
	}
	b, err := NewDhKeypair()
	if err != nil {
		t.Fatalf("NewDhKeypair b: %v", err)
	}
	sAB, err := a.DH(b.PublicBytes())
	if err != nil {
		t.Fatalf("A×Bpub: %v", err)
	}
	sBA, err := b.DH(a.PublicBytes())
	if err != nil {
		t.Fatalf("B×Apub: %v", err)
	}
	if !bytes.Equal(sAB[:], sBA[:]) {
		t.Fatalf("随机 DH 不对称")
	}
	var z byte
	for _, x := range sAB {
		z |= x
	}
	if z == 0 {
		t.Fatalf("随机 DH 共享全零(异常)")
	}
}

// lowOrderPoints —— 7 个 RFC 7748 / libsodium 低序点(u-coord little-endian),来自 x/crypto
// curve25519/vectors_test.go 同款(jedisct1/libsodium crypto_scalarmult/curve25519/ref10)。
// 这些点使 X25519 输出全零(非贡献性 DH)→ 库 v0.54.0 委托 crypto/ecdh 在 NewPublicKey/ECDH 期即拒
// (库自述 curve25519.go:25-26「32B 输入下 error 当且仅当输出会全零」)。用它们钉死「库计算期拒低序点」
// 行为:未来升/降级 curve25519 若不再委托 ecdh,本测试会暴露。
var lowOrderPoints = [][KeyLen]byte{
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // identity(全零)
	{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// TestDH_LowOrderPointsRejected:7 个 RFC 7748 / libsodium 低序点 → DH 必返 ErrDhNonContributory
// (03 §3 line 91 铁律)。升级自旧 TestDH_AllZeroPeerRejected(只测全零 identity)—— 现覆盖全部小子群点,
// 钉死库 v0.54.0 计算期拒低序点行为(对照 x/crypto curve25519_test.go TestLowOrderPoints 同款向量)。
func TestDH_LowOrderPointsRejected(t *testing.T) {
	kp, err := NewDhKeypair()
	if err != nil {
		t.Fatalf("NewDhKeypair: %v", err)
	}
	for i, p := range lowOrderPoints {
		if _, err := kp.DH(p); err != ErrDhNonContributory {
			t.Fatalf("低序点[%d] 应返 ErrDhNonContributory,got err=%v", i, err)
		}
	}
}

// TestRandomHSNonce:16B + 两次不撞(锁长度 + 随机性 smoke)。
func TestRandomHSNonce(t *testing.T) {
	n, err := RandomHSNonce()
	if err != nil {
		t.Fatalf("RandomHSNonce: %v", err)
	}
	if len(n) != HsNonceLen {
		t.Fatalf("nonce len=%d want %d", len(n), HsNonceLen)
	}
	n2, err := RandomHSNonce()
	if err != nil {
		t.Fatalf("RandomHSNonce 2: %v", err)
	}
	if bytes.Equal(n[:], n2[:]) {
		t.Fatalf("两次随机 nonce 撞(异常)")
	}
}
