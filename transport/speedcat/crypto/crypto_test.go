package crypto

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

// katVectorsJSON —— 跨实现 KAT 单一真相(方案 2B),由 `cargo run -p kat-gen` 从 proto-core 活 oracle 生成。
// go:embed 随 crypto 包 re-vendor 一并带走(fork + Bettbox 同一份)→ **Go 端不再手抄 hex**,改一处 crypto.rs
// 只需重生 JSON,两端自动同步。
//
//go:embed testdata/kat_vectors.json
var katVectorsJSON []byte

// katVectors 解 committed KAT JSON 的 vectors 段(name→hex)。
var katVectors = func() map[string]string {
	var doc struct {
		Vectors map[string]string `json:"vectors"`
	}
	if err := json.Unmarshal(katVectorsJSON, &doc); err != nil {
		panic("parse kat_vectors.json: " + err.Error())
	}
	return doc.Vectors
}()

// katWant 取 committed KAT 向量 name 的期望字节(hex 解码);缺失即 fatal(名须与 kat-gen 的 rows 对齐)。
func katWant(t *testing.T, name string) []byte {
	t.Helper()
	h, ok := katVectors[name]
	if !ok {
		t.Fatalf("kat_vectors.json 无向量 %q(kat-gen 是否重生?)", name)
	}
	return mustHex(t, h)
}

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
	want := katWant(t, "derive_key_c2s")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("DeriveKey c2s key:\n got %x\nwant %x", got[:], want)
	}
}

// TestKAT_Blake3Mac —— BLAKE3 keyed_hash(MAC 模式)与 Rust 逐字节一致。
func TestKAT_Blake3Mac(t *testing.T) {
	var key Key
	copy(key[:], katPSK)
	got := Blake3Mac(key, katMacInput)
	want := katWant(t, "blake3_mac")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("Blake3Mac:\n got %x\nwant %x", got[:], want)
	}
}

// TestKAT_FastAuthKey —— k_auth = DeriveKey(AUTH_KEY_CTX, psk) 与 Rust 一致。
func TestKAT_FastAuthKey(t *testing.T) {
	var psk Psk
	copy(psk[:], katPSK)
	got := FastAuthKey(psk)
	want := katWant(t, "fast_auth_key")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("FastAuthKey:\n got %x\nwant %x", got[:], want)
	}
}

// TestKAT_FastAuthTag —— 快路 auth_tag 与 Rust 逐字节一致(方案 1B:ver_min=1, ver_max=1, caps_c=0x0101, max_bw_c=0x12345678)。
func TestKAT_FastAuthTag(t *testing.T) {
	var kAuth Key
	copy(kAuth[:], katWant(t, "fast_auth_key"))
	var exporter Key
	copy(exporter[:], katExporter)
	got := FastAuthTag(kAuth, exporter, 0x01, 0x01, 0x0101, 0x12345678)
	want := katWant(t, "fast_auth_tag")
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
		vec  string // kat_vectors.json 向量名
	}{
		{"c2s_key", sk.C2SKey[:], "session_c2s_key"},
		{"s2c_key", sk.S2CKey[:], "session_s2c_key"},
		{"c2s_nonce", sk.C2SNonce[:], "session_c2s_nonce"},
		{"s2c_nonce", sk.S2CNonce[:], "session_s2c_nonce"},
	}
	for _, c := range cases {
		want := katWant(t, c.vec)
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
		vec  string // kat_vectors.json 向量名
	}{
		{"c2s_key", sk.C2SKey[:], "session_stream1_c2s_key"},
		{"s2c_key", sk.S2CKey[:], "session_stream1_s2c_key"},
		{"c2s_nonce", sk.C2SNonce[:], "session_stream1_c2s_nonce"},
		{"s2c_nonce", sk.S2CNonce[:], "session_stream1_s2c_nonce"},
	}
	for _, c := range cases {
		want := katWant(t, c.vec)
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
	want := katWant(t, "aead_ct")
	if !bytes.Equal(ct, want) {
		t.Fatalf("AEADEncrypt:\n got %x\nwant %x", ct, want)
	}
}

// TestKAT_BuildNonce —— nonce = base[8:12] XOR ctr_be 与 Rust 逐字节一致(ctr=0x12345678)。
func TestKAT_BuildNonce(t *testing.T) {
	var base [NonceLen]byte
	copy(base[:], katNonceBase)
	got := BuildNonce(base, 0x12345678)
	want := katWant(t, "build_nonce")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("BuildNonce:\n got %x\nwant %x", got[:], want)
	}
}

// TestKAT_DisguiseHSInput —— 伪装路握手 MAC 输入明文与 Rust 逐字节一致(方案 1B:9 字段,含 ver_sel)。
func TestKAT_DisguiseHSInput(t *testing.T) {
	var shared Key
	copy(shared[:], katShared)
	var nc, ns [HsNonceLen]byte
	copy(nc[:], katNonceC)
	copy(ns[:], katNonceS)
	got := DisguiseHSInput(0x01, 0x01, 0x01, shared, nc, ns, 0x0100, 0x11223344, 0x55667788)
	want := katWant(t, "disguise_hs_input")
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
