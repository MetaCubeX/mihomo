// blake3.go —— BLAKE3 两模式:DeriveKey(KDF,域分离派生)/ Blake3Mac(MAC,keyed_hash)。
// 对照 Rust crypto.rs:43-53。**两模式 flag 不同**,Go 端 metacubex/blake3 经核验两模式齐备
// (`New(size,key)` len(key)==32 → FlagKeyedHash;`DeriveKey(...)` → FlagDeriveKeyContext→FlagDeriveKeyMaterial;见包注释)。
//
// **依赖对齐(D3,docs/19 §7-①):** 用 `github.com/metacubex/blake3`(mihomo 自身 transport/vless/encryption
// 同款)而非 zeebo/blake3 —— adapter 与 mihomo 依赖栈对齐,vendor 进 fork 时零新增外部依赖。metacubex/blake3
// v0.1.0 的 API **形不同而语义同**:无 zeebo 的 hasher 构造 `NewDeriveKey`/`NewKeyed`,但 `DeriveKey(out,ctx,src)`
// (过程式两步,flag 与 zeebo 同)与 `New(size,key)`(len(key)==32→FlagKeyedHash)达成字节级等价,KAT 守(8 向量锁)。

package crypto

import "github.com/metacubex/blake3"

// DeriveKey = `BLAKE3-DeriveKey(context, ikm)` → 32B(03 §3 域分离派生)。
//
// Rust: `blake3::derive_key(context, ikm)`(KDF 模式,内部 DERIVE_KEY_MATERIAL flag)。
// Go: `blake3.DeriveKey(out, context, ikm)` —— 先以 DERIVE_KEY_CONTEXT flag 哈希 context 得 context_key,
//
//	再以 DERIVE_KEY_MATERIAL flag 哈希 ikm,写满 out(len(out)=KeyLen=32)。两步 flag 与官方 BLAKE3 一致
//	(与 zeebo/blake3 的 NewDeriveKey 内部完全相同),KAT 实证字节级互通。
//
// context 必须是硬编码常串(域分离语义,非秘密)—— speedcat 各 context 见 crypto.go 常量块。
func DeriveKey(context string, ikm []byte) Key {
	var out Key
	blake3.DeriveKey(out[:], context, ikm) // 过程式:两步派生写满 out[:](KeyLen=32);out 值类型,return 拷贝。
	return out
}

// Blake3Mac = `BLAKE3-keyed_hash(key, input)` → 32B(03 §3 handshake_secret / auth_tag MAC)。
//
// Rust: `blake3::keyed_hash(key, input)`(MAC 模式,KEYED flag,key 恒 32B)。
// Go: `blake3.New(MacLen, key[:])`(len(key)==32 → 内部置 FlagKeyedHash;等价 zeebo NewKeyed 的 hasher
//
//	初态)→ Write(input)→ Sum 前 MacLen 字节。KAT 实证与 Rust keyed_hash 一致。
//
// key 是 [32]byte 定长(KeyLen)→ metacubex `New` 的「len(key) 须 32」恒满足(传短 key 会越界 panic,
// 但 [32]byte 输入不可达)。与 zeebo NewKeyed 不同,metacubex `New` 不返 error 故无需 fail-loud 守卫。
func Blake3Mac(key Key, input []byte) [MacLen]byte {
	h := blake3.New(MacLen, key[:]) // MacLen=32;key [32]byte → FlagKeyedHash(MAC 模式 hasher 初态)
	_, _ = h.Write(input)           // Hasher.Write 永不返错(hash.Hash 契约)
	var out [MacLen]byte
	copy(out[:], h.Sum(nil))
	return out
}
