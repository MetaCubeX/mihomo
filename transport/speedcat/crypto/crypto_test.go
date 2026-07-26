package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// seq 生成长 n 的字节序列,起点 start、步长 step(用于逐字节复刻 Rust KAT harness 的固定输入)。
func seq(start byte, n int, step int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = start + byte(i*step)
	}
	return b
}

// mustHex 解 KAT hex(测试期断言,失败即 fatal)。
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad KAT hex %q: %v", s, err)
	}
	return b
}

// 固定输入(逐字节复刻 Rust KAT harness,crates/proto-core/tests/kat_vectors.rs)。
// 任一改动会让 KAT 失效 —— 改前先重跑 Rust harness 取新向量。
var (
	katPSK       = seq(0x01, 32, 1) // 01..20
	katExporter  = seq(0xa0, 32, 1) // a0..bf
	katAEADKey   = seq(0x30, 32, 1) // 30..4f
	katNonce     = seq(0xf0, 12, 1) // f0..fb
	katNonceBase = seq(0x10, 12, 1) // 10..1b
	katShared    = seq(0x50, 32, 1) // 50..6f(disguise_hs_input 的 shared)
	katNonceC    = seq(0xc0, 16, 1) // c0..cf
	katNonceS    = seq(0xd0, 16, 1) // d0..df
	katMacInput  = []byte("speedcat kat mac input")
	katAAD       = []byte("aad-kat")
	katPT        = []byte("plaintext-kat-payload")
)

// TestKAT_DeriveKey —— BLAKE3 derive_key(KDF 模式)与 Rust 逐字节一致(承重 head risk)。
func TestKAT_DeriveKey(t *testing.T) {
	got := DeriveKey(C2SKeyCtx, katPSK)
	want := mustHex(t, "929852758fc379927ca093443dfe0b0742a0a5e82ecb3d2d3bb960338470d0c1")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("DeriveKey c2s key:\n got %x\nwant %x", got[:], want)
	}
}

// TestKAT_Blake3Mac —— BLAKE3 keyed_hash(MAC 模式)与 Rust 逐字节一致。
func TestKAT_Blake3Mac(t *testing.T) {
	var key Key
	copy(key[:], katPSK)
	got := Blake3Mac(key, katMacInput)
	want := mustHex(t, "3adeeba6b899cab7206e0496b48c81793d5cf40a64885ba089eea5e65f8315a7")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("Blake3Mac:\n got %x\nwant %x", got[:], want)
	}
}

// TestKAT_FastAuthKey —— k_auth = DeriveKey(AUTH_KEY_CTX, psk) 与 Rust 一致。
func TestKAT_FastAuthKey(t *testing.T) {
	var psk Psk
	copy(psk[:], katPSK)
	got := FastAuthKey(psk)
	want := mustHex(t, "e2397be01da089cbd2ba9750e21a39d0adfbf4c7808503754f92c8437bfd7f71")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("FastAuthKey:\n got %x\nwant %x", got[:], want)
	}
}

// TestKAT_FastAuthTag —— 快路 auth_tag 与 Rust 逐字节一致(ver=1, caps_c=0x0101, max_bw_c=0x12345678)。
func TestKAT_FastAuthTag(t *testing.T) {
	var kAuth Key
	copy(kAuth[:], mustHex(t, "e2397be01da089cbd2ba9750e21a39d0adfbf4c7808503754f92c8437bfd7f71"))
	var exporter Key
	copy(exporter[:], katExporter)
	got := FastAuthTag(kAuth, exporter, 0x01, 0x0101, 0x12345678)
	want := mustHex(t, "527fb773f65c6af7cf2cfd415a73704216f8e1a74f4d1bb7416ff5cfa0dc801c")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("FastAuthTag:\n got %x\nwant %x", got[:], want)
	}
}

// TestKAT_DeriveSessionKeys —— 四会话子密钥与 Rust 逐字节一致(IKM = exporter)。
func TestKAT_DeriveSessionKeys(t *testing.T) {
	var ikm Key
	copy(ikm[:], katExporter)
	sk := DeriveSessionKeys(ikm, WholeConnection)
	cases := []struct {
		name string
		got  []byte
		hex  string
	}{
		{"c2s_key", sk.C2SKey[:], "0fdcf4eb8f8b2b09aa319dde88890c252230ba1e1d7ef444cb032a2a693fca98"},
		{"s2c_key", sk.S2CKey[:], "7bb8a6d87c59fe9e65f701e9ad12333a9779555ac07864549ed151923633176f"},
		{"c2s_nonce", sk.C2SNonce[:], "5e4d2a1cfe4aef27a3b312ae"},
		{"s2c_nonce", sk.S2CNonce[:], "a50fef3fdf334acc7a6953b8"},
	}
	for _, c := range cases {
		want := mustHex(t, c.hex)
		if !bytes.Equal(c.got, want) {
			t.Fatalf("DeriveSessionKeys %s:\n got %x\nwant %x", c.name, c.got, want)
		}
	}
}

// TestKAT_DeriveSessionKeysStream1 —— Stream(1) 分离与 Rust 逐字节一致(方案 1A KDF diversifier 跨实现锁:
// 未来给快路加内层 AEAD、pooled 流翻 StreamDiv(id) 时两端不分叉)。
func TestKAT_DeriveSessionKeysStream1(t *testing.T) {
	var ikm Key
	copy(ikm[:], katExporter)
	sk := DeriveSessionKeys(ikm, StreamDiv(1))
	cases := []struct {
		name string
		got  []byte
		hex  string
	}{
		{"c2s_key", sk.C2SKey[:], "f66b93dbfbd84c2e4eb2a7856256339ca4e3d30cc59e57efbdf90b59a6e81aa5"},
		{"s2c_key", sk.S2CKey[:], "a93dc5bcd93d8a3308016a510403df9a6d86b96a9338b24fefb5c7a80fad0e9d"},
		{"c2s_nonce", sk.C2SNonce[:], "d5573c92b86881c55b72a0d2"},
		{"s2c_nonce", sk.S2CNonce[:], "19fd677795dc7eb5d504908e"},
	}
	for _, c := range cases {
		want := mustHex(t, c.hex)
		if !bytes.Equal(c.got, want) {
			t.Fatalf("DeriveSessionKeys Stream(1) %s:\n got %x\nwant %x", c.name, c.got, want)
		}
	}
}

// TestKAT_AEADEncrypt —— ChaCha20-Poly1305 ct‖tag 与 Rust 逐字节一致(37B = 21 ct + 16 tag)。
func TestKAT_AEADEncrypt(t *testing.T) {
	var key Key
	copy(key[:], katAEADKey)
	var nonce [NonceLen]byte
	copy(nonce[:], katNonce)
	ct, err := AEADEncrypt(key, nonce, katPT, katAAD)
	if err != nil {
		t.Fatalf("AEADEncrypt: %v", err)
	}
	want := mustHex(t, "dd705a86b472fc642bf95ec202069febaa756347240aa3444709b4a605b6dc98078334890b")
	if !bytes.Equal(ct, want) {
		t.Fatalf("AEADEncrypt:\n got %x\nwant %x", ct, want)
	}
}

// TestKAT_BuildNonce —— nonce = base[8:12] XOR ctr_be 与 Rust 逐字节一致(ctr=0x12345678)。
func TestKAT_BuildNonce(t *testing.T) {
	var base [NonceLen]byte
	copy(base[:], katNonceBase)
	got := BuildNonce(base, 0x12345678)
	want := mustHex(t, "10111213141516170a2d4c63")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("BuildNonce:\n got %x\nwant %x", got[:], want)
	}
}

// TestKAT_DisguiseHSInput —— 伪装路握手 MAC 输入明文与 Rust 逐字节一致(8 字段拼接)。
func TestKAT_DisguiseHSInput(t *testing.T) {
	var shared Key
	copy(shared[:], katShared)
	var nc, ns [HsNonceLen]byte
	copy(nc[:], katNonceC)
	copy(ns[:], katNonceS)
	got := DisguiseHSInput(0x01, 0x01, shared, nc, ns, 0x0100, 0x11223344, 0x55667788)
	want := mustHex(t, "73706565646361742d76312d68730101505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6fc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf01001122334455667788")
	if !bytes.Equal(got, want) {
		t.Fatalf("DisguiseHSInput:\n got %x\nwant %x", got, want)
	}
}

// ---- 非固定向量的行为测(round-trip / 边界)----

// TestAEADRoundTrip seal→open 还原明文;tag 长度恒 16B。
func TestAEADRoundTrip(t *testing.T) {
	var key Key
	copy(key[:], katAEADKey)
	var nonce [NonceLen]byte
	copy(nonce[:], katNonce)
	ct, err := AEADEncrypt(key, nonce, katPT, katAAD)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != len(katPT)+TagLen {
		t.Fatalf("ct len = %d, want %d (pt + 16B tag)", len(ct), len(katPT)+TagLen)
	}
	pt, err := AEADDecrypt(key, nonce, ct, katAAD)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, katPT) {
		t.Fatalf("round-trip mismatch:\n got %x\nwant %x", pt, katPT)
	}
}

// TestAEADTamperRejected 改一字节密文 → 解密失败(鉴权,AEAD 完整性)。
func TestAEADTamperRejected(t *testing.T) {
	var key Key
	copy(key[:], katAEADKey)
	var nonce [NonceLen]byte
	copy(nonce[:], katNonce)
	ct, _ := AEADEncrypt(key, nonce, katPT, katAAD)
	ct[0] ^= 0xff
	if _, err := AEADDecrypt(key, nonce, ct, katAAD); err == nil {
		t.Fatal("tampered ct must fail AEAD auth")
	}
}

// TestAEADWrongKeyRejected 错密钥 → tag 不符 → 失败(伪装路错 PSK 首帧即此路径)。
func TestAEADWrongKeyRejected(t *testing.T) {
	var key Key
	copy(key[:], katAEADKey)
	var nonce [NonceLen]byte
	copy(nonce[:], katNonce)
	ct, _ := AEADEncrypt(key, nonce, katPT, katAAD)
	var wrong Key // 全零
	if _, err := AEADDecrypt(wrong, nonce, ct, katAAD); err == nil {
		t.Fatal("wrong key must fail AEAD auth")
	}
}

// TestBuildNonceCtrZero ctr=0 → nonce == base(XOR 0);高 8 字节恒不变。
func TestBuildNonceCtrZero(t *testing.T) {
	var base [NonceLen]byte
	copy(base[:], katNonceBase)
	got := BuildNonce(base, 0)
	if !bytes.Equal(got[:], base[:]) {
		t.Fatalf("ctr=0 nonce must equal base:\n got %x\nwant %x", got[:], base[:])
	}
	// 高 8 字节非零(本 KAT base 10..17)且 BuildNonce 不动它们。
	for i := 0; i < 8; i++ {
		if got[i] != base[i] {
			t.Fatalf("BuildNonce must not touch base[0:8] at byte %d", i)
		}
	}
}

// TestCTEq 常量时间比较语义:等 / 等长不等 / 异长。
func TestCTEq(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	if !CTEq(a, []byte{1, 2, 3, 4}) {
		t.Fatal("equal slices must compare true")
	}
	if CTEq(a, []byte{1, 2, 3, 5}) {
		t.Fatal("differing same-length slices must compare false")
	}
	if CTEq(a, []byte{1, 2, 3}) {
		t.Fatal("differing-length slices must compare false")
	}
}

// TestParsePSKHex valid / 0x 前缀 / 错长度 / 非法字符。
func TestParsePSKHex(t *testing.T) {
	// 64 hex:前 32 字节逐位 i+1(同 katPSK)。
	hexStr := hex.EncodeToString(katPSK)
	psk, err := ParsePSKHex(hexStr)
	if err != nil {
		t.Fatalf("valid psk: %v", err)
	}
	if !bytes.Equal(psk[:], katPSK) {
		t.Fatalf("psk round-trip:\n got %x\nwant %x", psk[:], katPSK)
	}
	// 0x 前缀(单次剥)。
	if _, err := ParsePSKHex("0x" + hexStr); err != nil {
		t.Fatalf("0x prefix should be stripped: %v", err)
	}
	if _, err := ParsePSKHex("0x0x" + hexStr); !errors.Is(err, ErrPSKHex) && !errors.Is(err, ErrPSKLen) {
		t.Fatalf("double 0x must fail (len≠64 or bad char): %v", err)
	}
	// 错长度。
	if _, err := ParsePSKHex("0102"); !errors.Is(err, ErrPSKLen) {
		t.Fatalf("short psk want ErrPSKLen, got %v", err)
	}
	// 非法字符。
	bad := make([]byte, len(hexStr))
	copy(bad, hexStr)
	bad[0] = 'z'
	if _, err := ParsePSKHex(string(bad)); !errors.Is(err, ErrPSKHex) {
		t.Fatalf("bad hex want ErrPSKHex, got %v", err)
	}
}
