// Package transport 实现 speedcat 协议传输层:TCP+TLS / QUIC dial + 取快路 exporter。
//
// 设计/流程:对照 docs/17 §3 L2 / docs/04 §2(传输 SSOT)/ ADR-007(快路 exporter 命门)。
// 产出的 [Conn] 同时是字节流(io.ReadWriteCloser —— L3 握手发/收 ClientHello/ServerHello 用)
// + exporter 探针(L3 用 exporter 算 auth_tag)。**exporter label 复用 [crypto.ExporterLabel]**
// (与 Rust proto-core/src/handshake.rs:16 逐字符一致),禁第二份字面量(协议两份实现,漂移 → 握手挂)。
//
// TLS 配置照 Rust 三分支(--insecure / --ca pin / 默认系统 CA;speedcat-cli cmd/mod.rs:46 build_client_cfg):
// InsecureSkipVerify=cfg.Insecure / RootCAs=pin(CAFile) / 默认系统 roots。MinVersion = TLS 1.3
// (speedcat exporter 在 TLS 1.3 + EMS 下成立;TLS 1.2 无 EMS,exporter 语义不同 —— ADR-007)。
// TCP arm 用 stdlib crypto/tls(成熟);QUIC arm 用 metacubex/tls(API 兼容,quic-go fork 同款,
// 集成 mihomo 时 import path 零摩擦 —— docs/17 §2 D3)。
//
// 冷热路径:dial/握手 = 冷路径(连接生命周期事件);热路径 relay 留 L4(ADR-005 零成本约束区不在此包)。
//
// dev 限制:L2 仅 dial + 取 exporter;relay / SOCKS5 / 握手字节编解码在 L3/L4。UDP datagram 留 L4。
package transport

import (
	"context"
	"errors"
	"io"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
)

// SpeedcatALPN 是 speedcat QUIC 的 ALPN(伪装值 = HTTP/3 的 "h3";镜像 Rust proto-core SPEEDCAT_ALPN)。
// QUIC 强制非空 ALPN(RFC 9001 §8.1 + 跨实现命门):Go quic-go dial Rust 空-ALPN server 报 0x178,两端固定同值即解。
// 值 = "h3"(ADR-017 / internal/25 M6 硬化):原 "speedcat/1" 在 QUIC Initial 的 ClientHello 明文可见
// (Initial 用公开 DCID 派生密钥,GFW 可解)= 自曝协议名;改 "h3" 与真实 HTTP/3 流量同名,消除 speedcat
// 专属 ALPN 指纹。pre-release wire break(部署群体=0;两端随此常量同步更新)。
const SpeedcatALPN = "h3"

// Kind 选传输(TCP+TLS / QUIC / 裸 TCP 伪装路),对应 Rust TransportAddr::TcpTls / Quic / RawTcp。
type Kind int

const (
	// KindTCP = TCP + TLS 1.3。
	KindTCP Kind = iota
	// KindQUIC = QUIC(metacubex/quic-go,multi-stream,ADR-008)。
	KindQUIC
	// KindRawTCP = 裸 TCP(**无 TLS exporter**;L4 新增)。exporter 不可用 → handshake.Client 路由
	// disguiseClient(eph DH ClientHello/ServerHello,双层 AEAD)→ 拨 Rust `server run --transport raw-tcp`
	// 的 disguise_server。**fail-safe:裸 TCP 无传输层加密/混淆**,仅 dev/测试/受控网络(伪装路双层 AEAD
	// 仍加密);生产伪装用 21 单栈(tls_cert/forge_consistent)。对照 Rust AnyConn::Raw + Transport::RawTcp。
	KindRawTCP
)

// Config 是 dial 配置(对齐 Rust TransportAddr:Host/Port/SNI/ALPN + client TLS 三分支)。
type Config struct {
	Host     string // server 主机(IP 或域名;QUIC 急切 DNS 解析同 Rust)
	Port     int    // server 端口
	SNI      string // TLS SNI;缺省 = Host(Rust config.rs:720)
	ALPN     string // ALPN;缺省 空(QUIC 可能强制非空 → SpeedcatALPN 兜底,决策 5)
	Insecure bool   // dev 旁路:接受任意证书(对应 Rust --insecure;fail-safe 危险默认拒)
	CAFile   string // pin CA PEM 文件(对应 Rust --ca;空 = 默认系统 roots)
}

// Conn 是 speedcat 传输层连接:字节流 + 快路 exporter 探针。
// 对照 Rust proto-core/src/transport.rs:TransportConn(export_keying_material 探针)
// + AsyncRead/AsyncWrite(字节流;QUIC 取一个 bidi stream 当流)。
type Conn interface {
	io.ReadWriteCloser
	// Exporter 取快路 exporter(ADR-007 密钥源):label=crypto.ExporterLabel,context 空,32B。
	// 对照 Rust handshake.rs:47 conn.export_keying_material(EXPORTER_LABEL, b"")。
	// 保留为便利方法(L3 握手用 stream label);底层委派 [Conn.ExporterWithLabel]。
	Exporter() ([crypto.KeyLen]byte, error)
	// ExporterWithLabel 按指定 label 取 TLS exporter(ADR-007 / ADR-009)。
	// stream label(crypto.ExporterLabel)= 握手 + relay Session 密钥源;UDP label(crypto.UDPExporterLabel)
	// = DatagramCipher 独立密钥源(与 stream 域分离)。对照 Rust TransportConn::export_keying_material(label, ctx)。
	// **L4 新增(L4 client datagram 路用):** 旧调用方仍用 Exporter()(委派此,stream label)→ 零破坏。
	ExporterWithLabel(label string) ([crypto.KeyLen]byte, error)
}

// DatagramConn 是 QUIC 原生 datagram 能力面(L4 新增;对照 Rust TransportConn::take_datagram)。
// 仅 QUIC conn 实现(TLS 1.3 over TCP 无 datagram → 流内隧道臂 fallback)。DialUDP 用类型断言探测:
// conn 实现此接口 + SupportsDatagrams() → datagram 臂(ADR-009 随机 nonce AEAD);否则 → 流隧道臂。
//
// **为何独立接口而非 Conn 方法:** TCP conn 物理上无 datagram,强加方法须返 error 语义模糊;独立接口 +
// type-assert 让 DialUDP 路径裁决在编译期外、运行时干净分支(对齐 Rust take_datagram()→Option)。
type DatagramConn interface {
	// SupportsDatagrams 两端都开 datagram 才为真(本地 Config.EnableDatagrams + 对端 transport param)。
	SupportsDatagrams() bool
	// SendDatagram 发一个不可靠 datagram(RFC 9221;无重传/无序)。过大 → DatagramTooLargeError。
	SendDatagram(p []byte) error
	// ReceiveDatagram 阻塞收一个 datagram(ctx 取消 / conn 关 → error)。
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	// MaxDatagramPayloadSize 单 datagram 明文上限(含 §6.1 header 预算;**已含 QUIC framing overhead**,
	// 调用方再扣 AEAD nonce/tag —— 对照 Rust dg_send.max_size();gotcha #2)。quic-go 无直接 max-size 方法,
	// 返 fallback 常量(仅 SendDatagram 的 DatagramTooLargeError 暴露真实上限,L4 MVP 不探)。
	MaxDatagramPayloadSize() int
}

// Dial 按 kind 建立传输连接(ctx 支持取消/超时),返回已握手 conn(exporter 此时可取)。
func Dial(ctx context.Context, cfg Config, kind Kind) (Conn, error) {
	switch kind {
	case KindTCP:
		return dialTCP(ctx, cfg)
	case KindQUIC:
		return dialQUIC(ctx, cfg)
	case KindRawTCP:
		return dialRawTCP(ctx, cfg)
	default:
		return nil, errors.New("transport: 未知 Kind")
	}
}
