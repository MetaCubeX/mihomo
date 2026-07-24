// reality_auth.go —— Reality 伪装路身份层 stealth auth 编解码(纯密码学,零网络;docs/05 §3.2)。
// 逐字节镜像 Rust crates/proto-core/src/reality_auth.rs;KAT(reality_auth_test.go)锁两端字节一致。
//
// **设计(标偷弃,CLAUDE.md §2.3):** 偷 XTLS REALITY 的「标准字段藏 auth」方案
// (`reference/REALITY/tls.go:229-264` 服务端解码 / `reference/Xray-core/transport/internet/reality/reality.go:139-175`
// 客户端注入):客户端临时 X25519 公钥进标准 keyShare[X25519];认证载荷藏进标准 sessionId
// (经 DH→HKDF→AES-GCM 加密);ClientHello.random 32B 劈 [20B salt][12B nonce]。服务端 peek
// ClientHello 原文 → 手解 → DH → HKDF → AES-GCM 解密比对 → 接管/转发。全程标准字段,对被动
// 观察者与真浏览器不可区分。
//
// **字节布局(零浪费,对齐 REALITY;逐字节复刻 Rust reality_auth.rs:44-66):**
//   - random[32] = [20 salt][12 nonce](salt=random[:20],nonce=random[20:32])
//   - AuthKey = HKDF-SHA256(salt=random[:20], ikm=X25519(priv,pub), info="REALITY") → 32B
//   - sessionId[32] = AES-256-GCM(key=AuthKey, nonce=random[20:32], pt=16B, aad)
//     —— 输出 16B ct + 16B GCM tag = 32B(Go Seal 与 Rust aes-gcm 都按 pt‖tag,逐字节一致)
//   - 明文 16B = [ver:1][reserved:3=0][time:4 BE][short_id:8]
//
// **AAD = sessionId 段清零后的 ClientHello 原文(REALITY 精妙):** 两端都把 sessionId 段清零
// 再作 AAD → 与密文内容解耦(无论密文是什么,AAD 固定用「清零版 CH」)。本模块 aad 参数 = 该
// 清零版 CH,由调用方(C7b transport/reality.go utls 注入时清零 sessionId 段)负责构造;本模块
// 纯字节进字节出,不碰 TLS 结构。
//
// **两层 auth 分域(承重,docs/05 §3.3):** 本模块产的 AuthKey(HKDF 后)**只作门卫**(决定
// 接管/转发 + C2 cert 签名域 HMAC key),**不进 speedcat 会话密钥派生,也不进 rustls TLS 流量密钥派生**
// → rustls/TLS 状态机零改。会话密钥由接管后内层 disguise 协议(eph DH + PSK)产;RealityConn
// exporter 返 Err → 强制内层 disguise。身份层 KDF = HKDF-SHA256(对齐 REALITY 生态),会话层 KDF =
// BLAKE3(crypto.rs),刻意分域互不污染。
//
// **HKDF-SHA256 而非 blake3:** 对齐 REALITY 生态约定(info="REALITY",salt=random[:20]),便于
// 跨实现(本 Go adapter ↔ Rust 服务端)逐字节镜像 + KAT 对齐。blake3 是 speedcat 内层会话 KDF,
// 身份层借生态标准。
//
// **返 error 不 panic**(§6.1):本包会被 mihomo 长跑宿主 import,panic 会 kill 整进程而非断一条
// 连接 —— 库不替宿主做 abort 决策。AEAD/HKDF 失败仅返 error,调用方(transport/reality.go)据此
// 判定转发 dest(无凭据探测者场景)。

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Reality 身份层常量(对照 Rust reality_auth.rs:44-66)。逐字节锁布局,任一改动须同步 Rust + 重跑 KAT。
const (
	// RealityHKDFInfo HKDF info 标签(对齐 XTLS REALITY 生态;reference/REALITY/tls.go:233)。
	RealityHKDFInfo = "REALITY"

	// RandomLen ClientHello.random 32B 布局总长。
	RandomLen = 32
	// SaltLen random[:20] → HKDF salt。
	SaltLen = 20
	// GcmNonceLen random[20:32] → AES-GCM nonce(12B)。
	GcmNonceLen = 12

	// SessionCTLen sessionId 密文 32B = 16B 明文 + 16B GCM tag。
	SessionCTLen = 32
	// SessionPTLen 认证载荷明文 16B。
	SessionPTLen = 16

	// AuthVersion 认证载荷明文的版本字节 = speedcat ProtocolVersion(对照 Rust AUTH_VERSION)。
	AuthVersion = ProtocolVersion
	// ShortIDLen short_id 固定 8B(REALITY ClientShortId 同尺寸)。
	ShortIDLen = 8

	// MaxTimeDiffSecs time 容差窗口(秒):防重放 + 客户端时钟漂移(REALITY 默认 MaxTimeDiff 同为分钟级)。
	MaxTimeDiffSecs int64 = 120
)

// AuthPayload sessionId 加密前的明文(REALITY plainText[:16],tls.go:243-251)。
// 布局 [ver:1][reserved:3=0][time:4 BE][short_id:8] = 16B(对照 Rust AuthPayload)。
// 值类型:跨 goroutine 复制零共享(热路径无锁,ADR-005;此为冷路径握手期,仍值语义统一)。
type AuthPayload struct {
	Version byte             // [0] = ProtocolVersion(校验须匹配)
	Time    uint32           // [4:8] BE unix 秒(校验须在 MaxTimeDiffSecs 窗口内)
	ShortID [ShortIDLen]byte // [8:16] 短 ID(校验须命中服务端白名单)
}

// ToBytes 序列化成 16B(进 AES-GCM 的明文;对照 Rust AuthPayload::to_bytes)。
// b[1:4] reserved 恒 0(对齐 REALITY 的 ver_xyz/reserved 结构)。
func (p AuthPayload) ToBytes() [SessionPTLen]byte {
	var b [SessionPTLen]byte
	b[0] = p.Version
	// b[1:4] reserved = 0(默认零值,不动)。
	binary.BigEndian.PutUint32(b[4:8], p.Time)
	copy(b[8:16], p.ShortID[:])
	return b
}

// AuthPayloadFromBytes 从 16B 反序列化(不校验;校验归 Validate;对照 Rust from_bytes)。
func AuthPayloadFromBytes(b [SessionPTLen]byte) AuthPayload {
	var p AuthPayload
	p.Version = b[0]
	p.Time = binary.BigEndian.Uint32(b[4:8])
	copy(p.ShortID[:], b[8:16])
	return p
}

// Validate 校验:version 匹配 + time 在窗口内 + short_id 命中白名单(对照 REALITY tls.go:257-260
// + Rust AuthPayload::validate)。short_id 比对走常量时间 CTEq(防时序侧信道,对照 crypto.rs::ct_eq)。
//
// now 由调用方传(测试可注入固定时间;生产用 uint32(time.Now().Unix()))。
func (p AuthPayload) Validate(now uint32, allowed [][ShortIDLen]byte) bool {
	if p.Version != AuthVersion {
		return false
	}
	diff := int64(p.Time) - int64(now)
	if diff < 0 {
		diff = -diff
	}
	if diff > MaxTimeDiffSecs {
		return false
	}
	for _, sid := range allowed {
		if CTEq(sid[:], p.ShortID[:]) {
			return true
		}
	}
	return false
}

// ---- DH + HKDF:派生 AuthKey(门卫密钥,不进会话派生)----

// DeriveSharedSecret 算 X25519(myPriv, peerPub) → 32B 原始共享密钥 + contributory 校验
// (防小子群攻击,对照 dh.go DhKeypair.DH + Rust reality_auth.rs::derive_shared_secret)。
//
// 客户端:(ephPriv, serverPubStatic);服务端:(serverPrivStatic, ephPub) —— DH 对称,两端共享密钥相同。
//
// 两道互补防线(对照 dh.go:8-17):① curve25519.X25519 v0.54.0 计算期即拒低序点(库自述:32B 输入下
// error 当且仅当输出会全零)→ 规约 ErrDhNonContributory;② 防御性二次全零校验(belt-and-suspenders)。
func DeriveSharedSecret(myPriv [KeyLen]byte, peerPub [KeyLen]byte) ([KeyLen]byte, error) {
	shared, err := curve25519.X25519(myPriv[:], peerPub[:])
	if err != nil {
		// 库计算期拒低序/无效公钥 → 规约 ErrDhNonContributory(对照 dh.go:69-72)。
		return [KeyLen]byte{}, ErrDhNonContributory
	}
	// 防御性二次全零校验(防小子群/无效公钥攻击,03 §3 line 91;对照 dh.go:74-86)。
	var z byte
	for _, b := range shared {
		z |= b
	}
	if z == 0 {
		return [KeyLen]byte{}, ErrDhNonContributory
	}
	var k [KeyLen]byte
	copy(k[:], shared)
	return k, nil
}

// HkdfRealityKey HKDF-SHA256(salt=random[:20], ikm=shared, info="REALITY") → 32B AES key
// (REALITY tls.go:233;对照 Rust hkdf_reality_key)。
//
// REALITY 把原始 DH 共享密钥当 IKM(非直接当 key),再 HKDF-Extract+Expand 成 32B。本函数返
// HKDF 后的 32B:既作本模块 AES key,又作 C7b 客户端 cert 签名域 HMAC key(HMAC-SHA512(AuthKey,
// cert_der 签名域清零版);藏 ed25519 cert 末 64B 签名域,对照 Rust proto-tls/src/cert.rs + ADR-012)。
//
// Go x/crypto/hkdf.New(hash, secret, salt, info):secret=IKM=shared,salt=random[:20],info="REALITY"。
// 与 Rust Hkdf::<Sha256>::new(Some(salt), ikm).expand(info) 逐字节同(同 spec HKDF-SHA256)。
func HkdfRealityKey(shared [KeyLen]byte, random [RandomLen]byte) ([KeyLen]byte, error) {
	r := hkdf.New(sha256.New, shared[:], random[:SaltLen], []byte(RealityHKDFInfo))
	var out [KeyLen]byte
	// ReadFull:out 恰 32B ≤ 255*hashLen(255*32),数学上必读满;失败仅 Reader 异常 → 包 error(库不 panic)。
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return [KeyLen]byte{}, fmt.Errorf("crypto: REALITY HKDF expand 失败: %w", err)
	}
	return out, nil
}

// ---- AES-256-GCM:sessionId 加密/解密 ----

// SealSession 加密认证载荷 → sessionId 32B 密文(客户端侧;对照 Xray reality.go:174 Seal +
// Rust seal_session)。
//
//   - hkdfKey = HkdfRealityKey(32B → AES-256)
//   - random = ClientHello.random([20 salt][12 nonce]);nonce 取 random[SaltLen:] = random[20:32] 12B
//   - aad = sessionId 段清零后的 ClientHello 原文(调用方负责清零)
//
// Go cipher.NewGCM(block).Seal(dst, nonce, pt, aad) 输出 = pt‖tag,与 Rust aes-gcm 逐字节一致
// (16B pt + 16B tag = 32B ct)。Seal 仅 nonce 长度错时 panic —— [12]byte 保证,不可达。
func SealSession(
	hkdfKey [KeyLen]byte,
	random [RandomLen]byte,
	payload AuthPayload,
	aad []byte,
) ([SessionCTLen]byte, error) {
	block, err := aes.NewCipher(hkdfKey[:])
	if err != nil {
		// 不可达:[32]byte key 恒满足 aes-256 的 16/24/32 要求。
		return [SessionCTLen]byte{}, fmt.Errorf("crypto: REALITY aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return [SessionCTLen]byte{}, fmt.Errorf("crypto: REALITY cipher.NewGCM: %w", err)
	}
	pt := payload.ToBytes()
	nonce := random[SaltLen:] // 12B(= GcmNonceLen)
	ct := gcm.Seal(nil, nonce, pt[:], aad)
	// 断言长度防未来 AEAD 库行为漂移(对照 Rust seal_session 长度断言)。
	if len(ct) != SessionCTLen {
		return [SessionCTLen]byte{}, fmt.Errorf("crypto: REALITY seal 输出非 %dB(收到 %dB)", SessionCTLen, len(ct))
	}
	var out [SessionCTLen]byte
	copy(out[:], ct)
	return out, nil
}

// OpenSession 解密 sessionId 32B 密文 → 16B 明文(服务端侧;对照 REALITY tls.go:245 Open +
// Rust open_session)。**不**校验 version/time/short_id(归 Validate);只做 AEAD 解密 + 完整性校验
// (GCM tag 不匹配 → err,调用方据此决定转发 dest)。
func OpenSession(
	hkdfKey [KeyLen]byte,
	random [RandomLen]byte,
	sessionCT [SessionCTLen]byte,
	aad []byte,
) ([SessionPTLen]byte, error) {
	block, err := aes.NewCipher(hkdfKey[:])
	if err != nil {
		return [SessionPTLen]byte{}, fmt.Errorf("crypto: REALITY aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return [SessionPTLen]byte{}, fmt.Errorf("crypto: REALITY cipher.NewGCM: %w", err)
	}
	nonce := random[SaltLen:]
	pt, err := gcm.Open(nil, nonce, sessionCT[:], aad)
	if err != nil {
		// 密文/完整性/AAD 不匹配 → err(无凭据探测者 / 篡改 / 错密钥 都落此);调用方据此转发 dest。
		return [SessionPTLen]byte{}, fmt.Errorf("crypto: REALITY open 失败(密文/完整性/AAD 不匹配): %w", err)
	}
	if len(pt) != SessionPTLen {
		return [SessionPTLen]byte{}, fmt.Errorf("crypto: REALITY open 输出非 %dB(收到 %dB)", SessionPTLen, len(pt))
	}
	var out [SessionPTLen]byte
	copy(out[:], pt)
	return out, nil
}

// ---- 高层组合(便利;两端各一,封装 DH+HKDF+AEAD)----

// ClientEncode 客户端编码:DH + HKDF + AES-GCM seal → (sessionId 密文, AuthKey)。
// 对照 Rust client_encode。AuthKey 返给调用方(C7b):用它校验服务端 cert 末 64B 签名域 HMAC
// (HMAC-SHA512(AuthKey, cert_der 签名域清零版),取 cert.Signature 比对)。eph 密钥由调用方生成
// (DhKeypair / utls 自带 keyshare 私钥)。
func ClientEncode(
	serverPub [KeyLen]byte,
	ephPriv [KeyLen]byte,
	random [RandomLen]byte,
	payload AuthPayload,
	aad []byte,
) (sessionCT [SessionCTLen]byte, authKey [KeyLen]byte, err error) {
	shared, err := DeriveSharedSecret(ephPriv, serverPub)
	if err != nil {
		return [SessionCTLen]byte{}, [KeyLen]byte{}, err
	}
	authKey, err = HkdfRealityKey(shared, random)
	if err != nil {
		return [SessionCTLen]byte{}, [KeyLen]byte{}, err
	}
	sessionCT, err = SealSession(authKey, random, payload, aad)
	if err != nil {
		return [SessionCTLen]byte{}, [KeyLen]byte{}, err
	}
	return sessionCT, authKey, nil
}

// ServerDecode 服务端解码:DH + HKDF + AES-GCM open → (payload, AuthKey)。
// 对照 Rust server_decode。AEAD 失败(无凭据/篡改/错密钥)或 contributory 失败 → err
// (调用方据此**转发 dest**)。
func ServerDecode(
	serverPriv [KeyLen]byte,
	ephPub [KeyLen]byte,
	random [RandomLen]byte,
	sessionCT [SessionCTLen]byte,
	aad []byte,
) (payload AuthPayload, authKey [KeyLen]byte, err error) {
	shared, err := DeriveSharedSecret(serverPriv, ephPub)
	if err != nil {
		return AuthPayload{}, [KeyLen]byte{}, err
	}
	authKey, err = HkdfRealityKey(shared, random)
	if err != nil {
		return AuthPayload{}, [KeyLen]byte{}, err
	}
	pt, err := OpenSession(authKey, random, sessionCT, aad)
	if err != nil {
		return AuthPayload{}, [KeyLen]byte{}, err
	}
	return AuthPayloadFromBytes(pt), authKey, nil
}
