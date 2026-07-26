// Package crypto 实现 speedcat 协议的密码学原语与密钥派生 —— BLAKE3(KDF+MAC)/
// ChaCha20-Poly1305 AEAD / nonce 构造 / 会话密钥派生 / 快路 auth_tag(快路 / 伪装路 / AEAD+nonce)。
//
// 这是 L4 A2(五层 proto 库)的第 2 层:纯密码学,零网络,零 I/O。只依赖
// `metacubex/blake3`(mihomo transport/vless/encryption 同款,对齐)+ `golang.org/x/crypto`
// (chacha20poly1305 + curve25519 后续 handshake 用),都是 mihomo / sing 生态既有依赖(D3)。
//
// **设计铁律:与 Rust 端 `crates/proto-core/src/crypto.rs` 逐字节一致。** speedcat 是协议两份
// 实现(Rust 内核 + Go adapter,以 SSOT 对照,见 docs/09 §5.5),密码学层任何字节分叉
// 都会让两端握手不上 —— 故本包每个函数都有 KAT(known-answer test),向量为 Rust 端实测印出后
// 冻进 `crypto_test.go`(Rust 当 oracle,跨实现一致性铁证,见承重风险)。
//
// **承重风险已解:** BLAKE3 有两种工作模式,Rust 用 `blake3::derive_key`(KDF 模式,
// DERIVE_KEY_MATERIAL flag)派密钥、`blake3::keyed_hash`(MAC 模式,KEYED flag)算 MAC。Go 端
// `metacubex/blake3` v0.1.0 经核验**同时支持**两种模式(`DeriveKey(out,ctx,src)` 用 Flag_DeriveKeyContext→
// Flag_DeriveKeyMaterial;`New(size,key)` len(key)==32 用 Flag_Keyed),flag 值与官方 BLAKE3 一致
// (1<<4 / 1<<5 / 1<<6)→ 两端字节级互通,KAT 实证(见 blake3_test.go)。
//
// **API 形不同语义同(承重):** metacubex/blake3 v0.1.0 早于 zeebo/blake3 v0.2.4 的
// hasher 构造 API —— **无** `NewDeriveKey`/`NewKeyed`,改为过程式 `DeriveKey(out,ctx,src)`(一步到位)
// + 通用 `New(size,key)`(len(key)==32 → keyed)。两者 flag 初态与 zeebo 完全相同 → 输出字节级等价,
// 由 8 KAT 向量锁(改 import 前后同款 Rust oracle 冻的向量不变即证)。
//
// **冷热路径边界:** 本包是热路径(relay/AEAD/帧)的底层。AEAD seal/open 各 1 次 alloc
// (与 Rust 端 Session 同成本),MVP 先正确,原地零拷贝留收尾(同 Rust)。
// **禁在 seal/open 里打日志**(每包日志 5G→1G 塌)。
package crypto

// 长度常量(对照 Rust crypto.rs:13-17)。
const (
	KeyLen     = 32 // 密钥/PSK/BLAKE3 输出长度
	NonceLen   = 12 // ChaCha20-Poly1305 IETF nonce(IETF 96-bit,非 orig 64-bit)
	MacLen     = 32 // BLAKE3 keyed_hash / derive_key 输出(auth_tag / handshake_secret)
	TagLen     = 16 // ChaCha20-Poly1305 tag
	HsNonceLen = 16 // 伪装路 nonce_c / nonce_s 随机(ClientHello/ServerHello)
	PskHexLen  = 64 // PSK hex 字符数(KeyLen × 2)
)

// 协议版本(对照 Rust PROTOCOL_VERSION = 0x01,lib.rs:45)。auth_tag / 握手帧绑定它。
const ProtocolVersion byte = 0x01

// 本端支持的版本范围(方案 1B 版本协商;对照 Rust lib.rs VERSION_MIN/VERSION_MAX)。当前退化
// min == max == 0x01,但协商机器就位:未来加不兼容 wire 版本只需上调 VersionMax。握手 ClientHello /
// FastHello 携客户端 [ver_min, ver_max],服务端与本端范围取交集选最高(见 handshake.negotiateVersion)。
const (
	VersionMin byte = 0x01
	VersionMax byte = ProtocolVersion
)

// 密钥派生 context 字符串(域分离)。与 Rust crypto.rs:193-196 逐字符一致 ——
// context 是 BLAKE3 derive_key 的域分离输入,任一字符差异 → 派生密钥完全不同 → 握手挂。
const (
	C2SKeyCtx     = "speedcat-v1 c2s key"
	S2CKeyCtx     = "speedcat-v1 s2c key"
	C2SNonceCtx   = "speedcat-v1 c2s nonce"
	S2CNonceCtx   = "speedcat-v1 s2c nonce"
	StreamDivCtx  = "speedcat-v1 stream-div" // KDF diversifier(方案 1A;仅 StreamDiv 经此,WholeConnection 不经)
	HSCtx         = "speedcat-v1-hs"         // 伪装路握手 MAC 输入前缀
	AuthKeyCtx    = "speedcat-v1 auth key"   // 快路 k_auth = DeriveKey(this, psk)
	FastAuthMsg   = "speedcat-v1 fast-auth"  // 快路 auth_tag MAC 明文前缀
	ExporterLabel = "speedcat-v1 exporter"   // TLS exporter label(handshake.rs:16)
	// UDPExporterLabel UDP datagram 独立 AEAD 上下文(DatagramCipher)的 exporter label。
	// 与 stream 的 ExporterLabel **域分离** → 独立 32B 密钥(对照 Rust proto-core/src/datagram.rs:33)。
	// datagram 路两端各派此 label 的 exporter → 字节一致;若误用 ExporterLabel → 两端 key 仍一致但与
	// stream 同 key(datagram / stream 不该共享密钥),且与 Rust 端(用此 label)key 不同 → 跨实现 datagram 全解密失败。
	// **协议两份实现,label 字面量必须逐字符一致**(漂移 → 单向解密挂)。
	UDPExporterLabel = "speedcat-udp-v1"
)

// Key / Psk —— 32B 定长,值类型(对照 Rust type Key = [u8; KEY_LEN])。
// 用定长数组而非 slice:① 长度编译期保证(传给 BLAKE3/AEAD 无需运行期校验);
// ② 值语义,跨 goroutine 复制零共享(热路径无锁)。
type (
	Key [KeyLen]byte
	Psk [KeyLen]byte
)

// SessionKeys —— 从 IKM(伪装路=handshake_secret / 快路=exporter)派生的四会话子密钥
// (对照 Rust crypto.rs:198-204)。c2s/s2c 方向分离:每方向独立 key + nonce,AEAD 双向不互扰。
type SessionKeys struct {
	C2SKey   Key            // client→server 方向 AEAD 密钥
	S2CKey   Key            // server→client 方向 AEAD 密钥
	C2SNonce [NonceLen]byte // client→server 方向 nonce 基(DeriveKey 前 12B)
	S2CNonce [NonceLen]byte // server→client 方向 nonce 基
}

// CTEq 常量时间比较(auth_tag / 握手 MAC 校验,避时序侧信道)。长度不等直接 false,
// 否则逐字节 OR 累积差(对照 Rust crypto.rs:180-189)。Go 标准库 crypto/subtle 语义一致,
// 这里包一层保留与 Rust 同名的 API(便于逐函数对照)。
func CTEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ParsePSKHex 解析 64-hex PSK 字符串 → 32B(对照 Rust parse_psk_hex,crypto.rs:27-41)。
// 允许单次 `0x` 前缀(剥一次,非反复剥 —— 与 Rust strip_prefix 语义一致)。长度非 64 或含
// 非 hex 字符 → 错误(fail-loud)。
//
// 注意:凭据管理铁律—— PSK 经此解析后进内存;调用方勿把明文 PSK 进日志。
func ParsePSKHex(s string) (Psk, error) {
	hexStr := s
	if len(hexStr) >= 2 && hexStr[0] == '0' && (hexStr[1] == 'x' || hexStr[1] == 'X') {
		hexStr = hexStr[2:]
	}
	if len(hexStr) != PskHexLen {
		return Psk{}, ErrPSKLen
	}
	var out Psk
	for i := 0; i < KeyLen; i++ {
		hi, ok1 := hexNibble(hexStr[2*i])
		lo, ok2 := hexNibble(hexStr[2*i+1])
		if !ok1 || !ok2 {
			return Psk{}, ErrPSKHex
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

// hexNibble 单个 hex 字符 → 4-bit 值(小工具,ParsePSKHex 用)。
func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
