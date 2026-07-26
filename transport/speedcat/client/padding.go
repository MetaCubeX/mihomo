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
	"os"
	"sync"
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

// ---- bulk 切片塑形 opt-in(ADR-016 §5 留后 · 落地;对照 Rust padding.rs bulk_shape_env)--------------
//
// `SPEEDCAT_BULK_SHAPE` 让 [pumpEncodeFast] 的 bulk 整段 Write 改为「按 target 切片循环 Write」—— 前 [stopN]
// 条 record 各切 ~target 量级(独立 TLS record,反 ~16401B bulk 指纹);`stopN` 后退原启发式(整段 Write,稳态
// 逐字不变)= **零稳态开销**(ADR-005)。**默认未设 → 不切片**(原 bulk 整段 Write,16401 = nginx/Apache 常见
// `max_fragment=16384` 默认,非 speedcat 专属 → 弱指纹,[internal/24] §4 据实记);opt-in 显式置位 → 切片
// (贴合 cloudflare ~1386 segment-aligned 基线;吞吐代价 box 权威门 defer)。
//
// **为何 env 而非 caps 位 / 非默认:** bulk-shape 是**服务端本地 emission 策略**,decode 盲丢 PADDING + 任意
// record 大小(shape-agnostic)→ 无两端协商;ride PADDING cap 会 default-ON(`Padding()` 是协商交集,TCP server
// 默认 offer)→ 与「opt-in default OFF」冲突。env 进程级 opt-in(systemd `Environment=` / launch script),
// Rust+Go 通用(`os.Getenv`),与 Rust `bulk_shape_env` 同款 OnceLock 模式(镜像既有一致)。
//
// **flush-per-record 风险(Go crypto/tls,中):** Go 对 sub-max-fragment `Write` **可能 coalesce**(不像 rustls
// `flush` 排空 plaintext buffer)→ 切片 record 可能被合并成一条大 record。但既有 Go 交互塑形(每 record 一次
// `conn.Write`)已依赖 per-Write emission 并随 ADR-016 shipped —— 即此风险**非切片新引入,是 Go upload 方向既有
// latent 问题**(Probe 2 测的是 server→client = Rust 方向)。处置:本轮 tee harness **加测 client→server(Go)
// 方向**(V2),据实报;Go bulk 切片 upload 方向 best-effort + 文档诚实记(Rust 下载方向已实证是主目标)。
//
// **吞吐(ADR-005):** 切片仅前 `stopN` 条 record(冷段,~8 次 Write/连接);稳态 `stopN` 后整段 Write 逐字不变 →
// 冷段有界、稳态零开销 = 按构造吞吐无损(box 门 defer 仅确认此构造结论)。

// bulkShapeFrom 解析 env 值 → 是否启用 bulk 切片塑形(纯函数,便于无全局态单测;对照 Rust bulk_shape_from)。
// 空串 / "0" → false(默认 OFF,原 bulk 整段 Write);其他非空 → true(按 target 切片循环 Write)。
func bulkShapeFrom(value string) bool {
	return !(value == "" || value == "0")
}

// bulkShapeCached / bulkShapeOnce 进程级缓存 env 读(对照 Rust OnceLock;ADR-005 env 读每进程一次)。
// sync.Once.Do 首调读 os.Getenv 后缓存,后续零成本(原子读 cached 值)。harness ON/OFF 是独立进程各自缓存语义正确。
var (
	bulkShapeOnce   sync.Once
	bulkShapeCached bool
)

// bulkShapeEnv 报告是否启用 bulk 切片塑形(opt-in SPEEDCAT_BULK_SHAPE;对照 Rust bulk_shape_env)。
// 首调 sync.Once 读 env 缓存,后续零成本(ADR-005)。默认未设 → false。
func bulkShapeEnv() bool {
	bulkShapeOnce.Do(func() {
		bulkShapeCached = bulkShapeFrom(os.Getenv("SPEEDCAT_BULK_SHAPE"))
	})
	return bulkShapeCached
}
