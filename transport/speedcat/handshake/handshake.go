// Package handshake 实现 speedcat 协议握手(L4 A2 五层 proto 库第 4 层):
// 在 L2 transport 产出的 [transport.Conn](字节流 + 快路 exporter 探针)上完成握手,产出 [Session]
// (会话密钥 + 协商 caps + max_bw)供 L4 client relay 用。
//
// # 两条路(按 exporter 探针路由)
//
//   - **快路**(exporter = 可取):无 ServerHello;auth_tag 搭 FastHello 同发(0-RTT)。
//     密钥从 exporter 派生;NO_INNER_AEAD **force 置位**(内层 AEAD 交 TLS record,splice 零拷贝成立)。
//   - **伪装路**(exporter = 不可取):eph DH ClientHello/ServerHello(+1 RTT)。
//     handshake_secret = blake3_mac(psk, hs_input);密钥从 handshake_secret 派生;NO_INNER_AEAD **force 清位**
//     (自带双层 AEAD)。**伪装路握手恒完成**(无显式 auth,密钥确认隐式于首帧 AEAD)—— 故仅「握手完成」
//     不证 PSK 正确(确凿鉴权见 L4 真 relay 或 doctor step2 抓出口 IP)。
//
// # 架构不变量(表)
//
// 路径 = exporter 探针,路径决定内层 AEAD,二者一对一绑定:
//
//	快路 (exporter 取到) ⇒ NO_INNER_AEAD 置位
//	伪装路 (exporter 不可取) ⇒ NO_INNER_AEAD 清位
//
// 各 client 构造 caps 时 force 该位;[Session] 从 caps.NoInnerAEAD() 派生 crypto flag(单一真相源,
// 闭合 HIGH-B 两套真相分叉)。⚠ 改路径语义必须同步改对应 force。
//
// # SSOT + 逐字节镜像
//
// 完全对照 Rust `crates/proto-core/src/handshake.rs`(SSOT):ClientHello 56B / ServerHello 55B /
// FastHello 40B 字节布局逐位一致(全大端)。speedcat 是协议两份实现(Rust 内核 + Go adapter),
// 握手帧任一字节分叉 → 两端握手挂 —— 故每个布局都用 Go↔Go self-test + 跨实现 e2e 钉死。
//
// 本轮 Go 只做 **client 侧**(adapter 是 outbound,拨到 Rust server);DisguiseServer/FastServer 是
// Rust server 侧的 Go 镜像,供 Go↔Go self-test 用,同时是 L4 client 的参考实现。
//
// # 冷热路径
//
// 握手 = 冷路径(每连接生命周期事件,可打日志、可 alloc)。热路径 relay(relay pump / AEAD per-packet)
// 留 L4,本包不触。帧编解码用定长 buffer + io.ReadFull/Write,无热路径铁律约束。
package handshake

import (
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/mihomo/transport/speedcat/transport"
	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// 帧长度(对照 Rust handshake.rs:69,71,198;全大端)。
const (
	// chLen ClientHello 长度:ver_min:u8 ver_max:u8 caps_c:u16 eph_c:32 nonce_c:16 max_bw_c:u32 = 56B。
	chLen = 1 + 1 + 2 + 32 + 16 + 4
	// shLen ServerHello 长度:ver:u8 caps_s:u16 eph_s:32 nonce_s:16 max_bw_s:u32 = 55B。
	shLen = 1 + 2 + 32 + 16 + 4
	// fhLen FastHello 长度(方案 1B,40B):ver_min:u8 ver_max:u8 caps_c:u16 max_bw_c:u32 auth_tag:32。
	fhLen = 1 + 1 + 2 + 4 + 32
)

// negotiateVersion 版本协商(方案 1B):客户端声明 [clientMin, clientMax],与本端 [VersionMin, VersionMax]
// 取交集选**最高** v*。交集空 / 范围非法 → ErrVersionUnsupported(铁律 2:调用方路由 fallback,不秒断)。
// 对照 Rust handshake::negotiate_version;当前退化 min==max==0x01 恒返 0x01。
func negotiateVersion(clientMin, clientMax byte) (byte, error) {
	lo := clientMin
	if crypto.VersionMin > lo {
		lo = crypto.VersionMin
	}
	hi := clientMax
	if crypto.VersionMax < hi {
		hi = crypto.VersionMax
	}
	if clientMin > clientMax || lo > hi {
		return 0, ErrVersionUnsupported
	}
	return hi, nil // v* = 交集最高版本
}

// 握手错误(对照 Rust Error::VersionUnsupported / AuthTagMismatch / Io;DH 全零错走 crypto.ErrDhNonContributory)。
var (
	// ErrVersionUnsupported 对端协议版本不在支持区间(对照 Rust Error::VersionUnsupported)。
	ErrVersionUnsupported = errors.New("handshake: 协议版本不支持")
	// ErrAuthTagMismatch 快路 auth_tag 常量时间比对不等(对照 Rust Error::AuthTagMismatch)。
	// 跨实现 e2e 里 Rust fast_server 验失败即拆连 → Go client 见 EOF(反推 PSK 错, 同款)。
	ErrAuthTagMismatch = errors.New("handshake: auth_tag 不匹配(快路鉴权失败)")
	// ErrHandshakeIO 帧 read/write I/O 失败(对照 Rust Error::Io);用 fmt.Errorf 多 %w 包裹,
	// 既可 errors.Is(_, ErrHandshakeIO) 又保留底层 io.EOF / ErrUnexpectedEOF 链(e2e 反推窗口用)。
	ErrHandshakeIO = errors.New("handshake: 帧 I/O 失败")
)

// Params 握手参数:本端声明的能力 + 声明带宽(对照 Rust HandshakeParams,handshake.rs:25-29)。
// MaxBandwidth=0 表未声明(Brutal 用;clamp_max_bw 见下)。
type Params struct {
	Caps         wire.Caps
	MaxBandwidth uint32
}

// Session 握手成果(L3 最小集):会话密钥 + 协商后的能力 + 最终带宽。
//
// 对照 Rust Session(session.rs),但 **tx/rx halves + ctr + 重放滑窗是 L4 relay 的事**(留后);
// L3 只产握手成果。NoInnerAEAD 从 Caps.CapNoInnerAEAD 派生(单一真相源,对齐 Rust caps.no_inner_aead())。
//
// **方向语义(留 L4):** 本包 [Client] 只做 client 侧(adapter outbound),故 relay 时 tx 用 Keys.C2SKey /
// rx 用 Keys.S2CKey(对照 Rust Session::new is_client=true)。DisguiseServer/FastServer 返回的 Session
// 是 server 侧(tx=s2c / rx=c2s)—— L4 不消费它们,仅 self-test 用。
type Session struct {
	Keys         crypto.SessionKeys // c2s/s2c 双向密钥(L4 按方向取)
	Caps         wire.Caps          // 协商后的能力(NO_INNER_AEAD 位已按路径 force)
	MaxBandwidth uint32             // 最终带宽(快路=client 声明;伪装 client=client 声明;伪装 server=clamp 后)
}

// Client 在已建连的 transport.Conn 上做 client 侧握手,按 exporter 探针自动路由(对照 Rust
// handshake.rs:33-53 顶层 role=Client 分支)。
//
//	exporter 取到 → fastClient(快路 0-RTT)
//	exporter 不可取 → disguiseClient(伪装路 eph DH +1 RTT)
//
// 注意:exporter 探针语义 = 「TLS 1.3 exporter 可取」(快路成立前提);裸 TCP / net.Pipe
// 无 exporter → 走伪装路(Go↔Go self-test 用 net.Pipe 即此)。
func Client(conn transport.Conn, psk crypto.Psk, params Params) (*Session, error) {
	exporter, err := conn.Exporter()
	if err == nil {
		return fastClient(conn, psk, params, exporter)
	}
	return disguiseClient(conn, psk, params)
}

// clampMaxBW 服务端对客户端声明带宽的策略 clamp(对照 Rust clamp_max_bw,handshake.rs:58-64,P2 HIGH-A):
// cap==0(本端不限)或 declared==0(客户端未声明)→ 透传;否则取 min。
// 仅 server 侧用(FastServer / DisguiseServer);client 侧记自身声明(乐观)。
func clampMaxBW(declared, cap uint32) uint32 {
	if cap == 0 || declared == 0 {
		return declared
	}
	if declared < cap {
		return declared
	}
	return cap
}

// wrapIO 包裹帧 I/O 错(对照 Rust `?` 透传 Error::Io)。多 %w 保链:errors.Is(_, ErrHandshakeIO)
// 与 errors.Is(_, io.EOF) 皆可(e2e 快路反推窗口探 EOF 用后者)。
func wrapIO(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrHandshakeIO, err)
}
