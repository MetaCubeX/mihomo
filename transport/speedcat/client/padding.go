// padding.go —— PADDING 塑形:动态 per-session 分布表(反 anytls 静态 md5「观察一次永久识别」;ADR-016 / 05 §4 / 21 铁律 4)。
//
// 镜像 Rust [crates/proto-core/src/padding.rs] 逐段(两端分布形态对齐 —— decoder 盲丢,但塑形形态一致利于跨
// 实现统计一致)。设计见该文件模块头 + internal/05 §4 / internal/21 §2。
//
// **设计:** 前 [stopN] 条 TLS record 按 chunked-HTTPS-like 分布带塑形(每条一个 `[lo,hi]` 目标大小带,
// per-conn PRNG 在带内取值 → 两连接 record 序列不同);stopN 后稳态直出(零开销,ADR-005)。encode 落
// [pumpEncodeFast] 快路分支;decode 两侧([pumpDecodeFast]/[pumpDecodeAead])无条件盲丢 Padding payload。
//
// **为何 `stop=8`(§2 原则3 标偷弃):** anytls `stop=8`(`padding.go`)与 naive `NumFirstPaddings=8` 两条
// 独立实现都收敛在「塑形前 8 条 record 后停」——两个独立数据点。speedcat 取同值(偷收敛点),弃 anytls 的
// 「静态 md5 分布表」改 per-session 动态 PRNG(反「观察一次永久识别」)。
//
// **PRNG:** 包 math/rand 的 `*Rand`(per-conn 1 次 crypto/rand 冷种子 → 跨连接独立序列)。padding 字节只需
// **统计随机**(明文进 tunnel 即被对端丢,非密码学秘密)→ OS 熵 1 次冷 seed 的快速 PRNG 足够(非每包 OsRng
// syscall);per-conn 独立 seed → 跨连接 record 序列各异(反静态指纹)。
//
// **热路径(ADR-005 合规):** 塑形仅前 stopN 条 record(连接冷段,PRNG fill ~stopN×1KB ≈ 8KB/连接);
// 稳态 bulk(stopN 后)pumpEncodeFast 逐字不变 = **零稳态开销**。[paddingScheme] / [*prng] 在 pumpEncodeFast
// 外构造一次(冷路径),循环内仅 [paddingScheme.target] / [*prng.fill](栈运算 + 1 次 memcpy,<stopN 次)。

package client

import (
	crand "crypto/rand"
	"encoding/binary"
	mrand "math/rand"
)

// stopN 塑形的前 N 条 record 数(借 anytls stop=8 + naive NumFirstPaddings=8 两独立收敛点;§2 原则3;对照 Rust STOP_N)。
// stopN 后稳态直出(零开销,ADR-005)。
const stopN = 8

// httpsLikeBands 编译期 HTTPS-like 分布带(对照 Rust HTTPS_LIKE_BANDS):前 stopN 条 record 各一个 [lo,hi] 目标
// 明文字节数(塑形时 pumpEncodeFast 攒到 target 即早 flush,短读则补 PADDING 到 target)。形态模仿 chunked HTTPS
// 早期 record 由小到中爬升(握手 / 响应头期小 record,渐增);per-conn PRNG 带内抖动 → 两连接 record 序列不同。
// 具体数值 留后 可配化(本轮硬编码合理 HTTPS-like 默认)。
var httpsLikeBands = [stopN]struct{ lo, hi int }{
	{160, 320},
	{240, 520},
	{360, 760},
	{520, 1040},
	{700, 1300},
	{900, 1500},
	{1000, 1600},
	{1100, 1630},
}

// paddingScheme PADDING 塑形方案(分布表;对照 Rust PaddingScheme)。冷路径构造一次进 pumpEncodeFast。
type paddingScheme struct {
	bands [stopN]struct{ lo, hi int }
}

// defaultPaddingScheme 默认 HTTPS-like 分布带(对照 Rust PaddingScheme::default_https;留后 可配化)。
func defaultPaddingScheme() paddingScheme {
	return paddingScheme{bands: httpsLikeBands}
}

// target 第 i 条塑形 record 的目标明文字节数(per-conn PRNG 在 [lo,hi] 带内抖动;对照 Rust PaddingScheme::target)。
// i >= stopN → 返 0(pumpEncodeFast 据此跳过塑形,稳态直出,ADR-005 零稳态开销)。
// 返 0 时调用方须视作「不塑形」(早 flush / 补 padding 均跳过)。
func (s paddingScheme) target(i int, p *prng) int {
	if i >= stopN {
		return 0
	}
	return p.genRange(s.bands[i].lo, s.bands[i].hi)
}

// prng per-conn 快速 PRNG(OS 熵 1 次冷 seed;padding 字节只需统计随机,非密码学秘密;对照 Rust Prng)。
// 包 math/rand 的 *Rand(per-conn 独立 seed → 跨连接 record 序列各异,反 anytls 静态 md5 指纹)。
type prng struct {
	r *mrand.Rand
}

// newPrngFromEntropy 从 OS 熵冷种子构造(per-conn 1 次;对照 Rust Prng::from_entropy)。
// crypto/rand 失败极罕见(系统熵池枯竭)→ 兜底固定种子(塑形仍工作,仅序列确定性 —— 安全无损:
// padding 非密码学秘密;fail-safe 非致命,正确性不依赖 padding)。
func newPrngFromEntropy() *prng {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return &prng{r: mrand.New(mrand.NewSource(0x7370636174))} // "spcat" 兜底种子
	}
	seed := int64(binary.LittleEndian.Uint64(b[:]))
	return &prng{r: mrand.New(mrand.NewSource(seed))}
}

// fill 填 dst 随机字节(PADDING body,明文进 tunnel 即被对端丢;对照 Rust Prng::fill_bytes)。
// math/rand 的 *Rand.Read 总写满 len(dst) 并返 (n,nil) —— 无 error 处理。
func (p *prng) fill(dst []byte) {
	_, _ = p.r.Read(dst)
}

// genRange [lo,hi] 闭区间取一值(分布带内抖动;对照 Rust Prng::gen_range)。
// lo>=hi → 返 lo(避 Intn(0) panic;对照 Rust 空区间兜底)。
func (p *prng) genRange(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	return lo + p.r.Intn(hi-lo+1)
}
