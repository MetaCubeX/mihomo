// quic_pool.go —— QUIC 客户端 1-conn-N-stream 池化(L4 收尾;镜像 Rust Stage 1 收尾
// QuicConnHandle / QuicPool / dial_or_reuse_quic —— proto-quic/src/transport.rs:136-188,619-690
// + speedcat-client/src/lib.rs:161-269)。
//
// # 为什么(兑现客户端侧前提)
//
// N 条 SOCKS5 CONNECT 复用 **1 条 QUIC conn**(各开 1 bidi stream):握手只付 1 次(省 N-1 RTT)、
// 单拥塞控制器、跨核派发 N 流(门②拓扑前提)。对照 Rust:`Client` 持 `Arc<QuicPool>`(Clone 共享)
// → N SOCKS5 conn 收敛到 1 QUIC conn。Go 等价:单一 `*Client` 被 accept loop 多 goroutine 共享,
// 其 `quicPool *QuicPool` 的 `sync.Mutex` 串行化建连决策。
//
// # 单 flight(Go 语义承重对照 Rust)
//
// Rust 用 `tokio::sync::Mutex` **持锁贯穿 `dial_quic_conn.await`**(冷启 N 并发首 dial 序列化 → 单 conn
// 无 orphan;快路 `drop(guard)` 后再 `open_stream` → 并发复用不序列化)。Go `sync.Mutex` 持锁贯穿阻塞
// `quic.DialAddr` **同样合法**:GMP 调度 park 阻塞中的 goroutine 而 mutex 留锁,**无 Rust
// `await_holding_lock` 死锁风险**(Go 阻塞不释放锁)。故近逐行镜像:
//   - **快路**(锁内 `isAlive()` 真 → 取 handle → `Unlock` → `openStream`,锁外 `OpenStreamSync` → 并发复用不序列化);
//   - **慢路**(持锁贯穿 `dialQUICConn` → 存 handle → `openStream`;冷启 N 并发首 dial 排队,只建 1 conn)。
// `go.mod` 无 `golang.org/x/sync`,**不引**(sync.Mutex 直译足够)。
//
// # 池化 = TCP-CONNECT only(对照 docs/09「池化与 UDP ASSOCIATE 干净分离」)
//
// 池化 conn 不 spawn datagram reader(`openStream` 返 `pooled=true` quicConn,Close 只关 stream);
// UDP ASSOCIATE 仍走 `Client.DialUDP` → `transport.Dial`(每 ASSOC fresh conn + reader)。两路 conn 物理隔离。
//
// # 快路密钥复用安全(对照 Rust guardrail)
//
// 同 conn 多 stream 共享一个 TLS session → 同 exporter → 同 `derive_session_keys` 输出。但快路
// `NO_INNER_AEAD` **不用**此密钥(只写 AAD 头 + 明文,机密性靠 QUIC conn 级 AEAD)→ 无 nonce-reuse。
// guardrail:未来若给快路加内层 AEAD,须按 quic stream-id diversify exporter context。
//
// # 冷热路径
//
// dial/握手 = 冷路径(连接生命周期事件);池锁只在冷路径建连时持有,relay/AEAD/帧编解码热路径不触此锁。
//
// dev 限制:每 conn datagram 能力 `EnableDatagrams=true`(与非池化路一致;池化路不读 datagram,能力闲置无害)。

package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	congestionv2 "github.com/metacubex/mihomo/transport/speedcat/congestion"
	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/quic-go"
)

// pooledHandle pool 视角的「一条可复用 QUIC conn」抽象(便于测试注入替身;*quic.Conn 经
// quicConnHandle 适配满足)。镜像 Rust QuicConnHandle 的 is_alive / open_stream 两能力。
type pooledHandle interface {
	// isAlive conn 仍活(未关)。对照 Rust is_alive = close_reason().is_none()。
	isAlive() bool
	// openStream 在已建连开一个 bidi stream,返池化 Conn(pooled=true → Close 只关 stream)。
	// 对照 Rust QuicConnHandle::open_stream(inline 构 QuicConn,datagram 强制 None)。
	openStream(ctx context.Context) (Conn, error)
}

// quicConnHandle 已建连的 QUIC conn 句柄(conn 级,跨 stream 复用)。持 *quic.Conn(cheap 句柄)。
// 对照 Rust QuicConnHandle { conn: QuinnConn, _endpoint: Arc<Endpoint> }:Go 的 *quic.Conn 自持
// endpoint(在飞 stream/句柄引用即续命),不需显式 Arc<Endpoint>(GC 兜底生命周期)。
type quicConnHandle struct {
	conn *quic.Conn
}

// isAlive conn 仍活。quic-go 的 *quic.Conn.Context() 返回「conn 关时 cancel」的 ctx
// (Connection 接口语义);Done 即已关。对照 Rust conn.close_reason().is_none()。
func (h *quicConnHandle) isAlive() bool {
	select {
	case <-h.conn.Context().Done():
		return false
	default:
		return true
	}
}

// openStream 在已建连开一个 bidi stream,返池化 quicConn(pooled=true:Close 只关 stream,
// 留父 conn 给后续 stream 复用;不 spawn datagram reader —— 对照 Rust open_stream 强制 datagram=None)。
// exporter 仍从父 conn 取(握手用;多 stream 共享,快路密钥复用安全见模块头)。
func (h *quicConnHandle) openStream(ctx context.Context) (Conn, error) {
	stream, err := h.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &quicConn{stream: stream, conn: h.conn, pooled: true}, nil
}

// QuicPool 至多持 1 quicConnHandle(N SOCKS5 conn 共享;Client 持 *QuicPool)。
// 对照 Rust QuicPool(Mutex<Option<QuicConnHandle>>)。
type QuicPool struct {
	mu     sync.Mutex
	handle pooledHandle
	// dial 建 QUIC conn 的函数(NewQuicPool 闭包 cfg;测试注入计数替身)。对照 Rust dial_quic_conn。
	dial func(ctx context.Context) (pooledHandle, error)
	// dials 慢路成功建连计数(client 侧 conn-count 可观测;对照 Rust QuicListener::conn_count)。
	// 冷启 N 并发 single-flight → 此值 = 1 即「N stream 收敛到 1 conn」铁证(跨实现 e2e 用)。
	dials atomic.Uint64
}

// NewQuicPool 构造池,dial 闭包 cfg(生产用;每次建连调 dialQUICConn)。池懒 dial(Client 启动不建连)。
func NewQuicPool(cfg Config) *QuicPool {
	return &QuicPool{dial: func(ctx context.Context) (pooledHandle, error) {
		return dialQUICConn(ctx, cfg)
	}}
}

// Dial 取一条池化 Conn(快路复用 / 慢路 single-flight dial)。对照 Rust dial_or_reuse_quic
// (speedcat-client/src/lib.rs:250-269)。返回的 Conn.Close() 只关 stream(池化语义);父 conn
// 由 pool 续命至 handle 死亡后下次慢路重 dial。
func (p *QuicPool) Dial(ctx context.Context) (Conn, error) {
	for {
		// ctx 取消兜底:避免快路 openStream 持续失败时的空转(ctx 取消 → 即时返)。
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// 快路:锁内判活取 handle,锁外 openStream(并发复用不序列化)。
		p.mu.Lock()
		if h := p.handle; h != nil && h.isAlive() {
			p.mu.Unlock()
			c, err := h.openStream(ctx)
			if err != nil {
				continue // handle 刚死(isAlive 与 OpenStreamSync 间竞态)→ 重判,下次 isAlive=false 走慢路。
			}
			return c, nil
		}

		// 慢路:持锁贯穿 dial(冷启 N 并发首 dial 排队 → 只建 1 conn 无 orphan;对照 Rust 持锁贯穿 dial_quic_conn)。
		h, err := p.dial(ctx)
		if err != nil {
			p.mu.Unlock()
			return nil, err
		}
		p.dials.Add(1) // 建连成功计数(client 侧 conn-count 可观测;single-flight 保证冷启 = 1)。
		c, err := h.openStream(ctx)
		if err != nil {
			// dial 成功但 open 失败 → 弃 handle(对照 Rust open_stream? 早返,handle drop 不入池)→ 返错。
			p.mu.Unlock()
			return nil, err
		}
		p.handle = h
		p.mu.Unlock()
		return c, nil
	}
}

// Dials 返回本池已成功建立的 QUIC conn 数(client 侧 conn-count 可观测;对照 Rust
// QuicListener::conn_count())。池化语义:N Dial 收敛到 1 conn → 此值应 = 1(冷启并发);
// 值 > 1 表示旧 conn 死后重 dial(对端关/网络断)。跨实现 e2e 用此断言「N stream 1 conn」。
func (p *QuicPool) Dials() uint64 { return p.dials.Load() }

// dialQUICConn 建 QUIC conn(不开 stream,不建 datagram reader;对照 Rust dial_quic_conn)。
// 复用 dialQUIC 的 TLS/qcfg 构造;池化路 openStream 独立调。非池化路 dialQUIC 亦经此(去重)。
func dialQUICConn(ctx context.Context, cfg Config) (*quicConnHandle, error) {
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	tlsCfg, err := quicTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	// EnableDatagrams=true 与非池化路一致(池化路不读 datagram,能力闲置无害;避免两份 qcfg)。
	qcfg := &quic.Config{EnableDatagrams: true}
	conn, err := quic.DialAddr(ctx, addr, tlsCfg, qcfg)
	if err != nil {
		return nil, fmt.Errorf("transport: quic dial (pool) %s: %w", addr, err)
	}
	// BBR parity(ADR-006/017):Rust transport.rs:651 在 TransportConfig 级设 BbrConfig → 每条 QUIC conn 跑 BBR;
	// quic-go 无 Config.CongestionControl 字段 → per-conn 后置注入(metacubex 库模型,非 quinn endpoint 级)。
	// cwnd=32 / profile=""(standard)对齐 mihomo tuic 默认(SetCongestionController cwnd==0→32、profile 空串→standard);
	// RTTStats 由 quic-go 在 SetCongestionControl 内自动注入(sent_packet_handler→cc.SetRTTStatsProvider)。
	// BBR-vs-CUBIC 差分是吞吐行为,仅真带宽路径可证(留 Phase 4 bench);本调证「wiring 正 + 不破功能」。
	conn.SetCongestionControl(congestionv2.NewBbrSender(congestionv2.GetInitialPacketSize(conn), 32, ""))
	return &quicConnHandle{conn: conn}, nil
}

// QuicHandle 一条已建连 QUIC **conn** 的 conn 级公开句柄(L4 收尾 A;对照 Rust quicConnHandle 的公开面)。
//
// # 为何需要 conn 级句柄(非 QuicPool.Dial 出的 stream)
//
// UDP N-ASSOC/conn(L4 收尾 A)要 **1 QUIC conn 承 N ASSOC**:各 ASSOC 各开 1 bidi stream
// (握手 + UdpAssociate 首帧),报文全走 conn 级 datagram(conn 级**单** reader 按 assoc_id demux)。
// QuicPool.Dial 每次**开一条 stream**(stream 级),不暴露 conn 级 datagram 入口 → 不敷 UDP 池用。
// 本句柄暴露:OpenStream(per-ASSOC 握手流)+ DatagramConn 面(conn 级 reader/sender)+ exporter
// (DatagramCipher 派生)。UDP 池(client 包)持 1 QuicHandle + 1 reader goroutine + per-assoc routes。
//
// **DatagramConn 面 = 父 conn 直委派**(无 stream):QuicHandle 本身 impl DatagramConn,SendDatagram/
// ReceiveDatagram/SupportsDatagrams 直调父 *quic.Conn(对照 quicConn 的同名方法,但 quicConn 需一个 stream
// 字段;QuicHandle 不开 stream → reader/sender 不浪费 stream 配额)。reader goroutine 是 conn 级**唯一**
// ReceiveDatagram 调用方(quic-go 单 owner/conn 语义,对照 Rust read_datagram 单 future/conn)。
//
// **与 QuicPool 的关系:** 独立(TCP CONNECT 池 vs UDP ASSOC 池物理隔离,对照 docs/09「池化与 UDP ASSOCIATE
// 干净分离」)。TCP CONNECT 走 QuicPool(stream 池);UDP ASSOC 走 client.udpPool(持 1 QuicHandle)。
// 两者各拨各的 QUIC conn(同时用 TCP+UDP = 2 conn,可接受;对照 Rust UDP 非 pool 每 ASSOC 1 conn)。
type QuicHandle struct {
	h *quicConnHandle
}

// DialQuicHandle 拨一条 QUIC conn → conn 级句柄(不开 stream;对照 Rust dial_quic_conn 返 QuicConnHandle)。
// 调用方(client UDP 池)持之,经 OpenStream 开 N stream + 经 DatagramConn 面 reader/sender。
func DialQuicHandle(ctx context.Context, cfg Config) (*QuicHandle, error) {
	h, err := dialQUICConn(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &QuicHandle{h: h}, nil
}

// OpenStream 在此 conn 上开一条新 bidi stream → 池化 Conn(pooled=true:Close 只关 stream,留父 conn)。
// 对照 quicConnHandle.openStream(UDP 池各 ASSOC 握手用)。exporter 取自父 conn(多 stream 共享,快路密钥
// 复用安全:同 conn 同 exporter,但快路 NO_INNER_AEAD 不用此 key → 无 nonce-reuse;guardrail 见 quic_pool 模块头)。
func (g *QuicHandle) OpenStream(ctx context.Context) (Conn, error) {
	return g.h.openStream(ctx)
}

// IsAlive conn 仍活(UDP 池做 liveness 过滤 + 决定重 dial;对照 quicConnHandle.isAlive)。
func (g *QuicHandle) IsAlive() bool {
	return g.h.isAlive()
}

// Close 关闭父 QUIC conn(UDP 池换 conn / Client 退时调;ApplicationErrorCode(0) 正常关)。
func (g *QuicHandle) Close() error {
	return g.h.conn.CloseWithError(quic.ApplicationErrorCode(0), "")
}

// ExporterWithLabel 按指定 label 取**父 conn**的 TLS exporter(L4 收尾 A;UDP 池派生 DatagramCipher 用
// crypto.UDPExporterLabel)。从父 conn 取(stream 无 ConnectionState),对照 quicConn.ExporterWithLabel。
func (g *QuicHandle) ExporterWithLabel(label string) ([crypto.KeyLen]byte, error) {
	var out [crypto.KeyLen]byte
	tlsState := g.h.conn.ConnectionState().TLS
	b, err := tlsState.ExportKeyingMaterial(label, nil, crypto.KeyLen)
	if err != nil {
		return out, fmt.Errorf("transport: quic handle exporter: %w", err)
	}
	copy(out[:], b)
	return out, nil
}

// Exporter 取快路 exporter(stream label;便利方法,委派 ExporterWithLabel)。对照 quicConn.Exporter。
func (g *QuicHandle) Exporter() ([crypto.KeyLen]byte, error) {
	return g.ExporterWithLabel(crypto.ExporterLabel)
}

// SupportsDatagrams 两端都开 datagram 才真(对照 quicConn.SupportsDatagrams;UDP 池路径裁决用)。
func (g *QuicHandle) SupportsDatagrams() bool {
	s := g.h.conn.ConnectionState().SupportsDatagrams
	return s.Local && s.Remote
}

// SendDatagram 发一个不可靠 datagram(父 conn 直委派;对照 quicConn.SendDatagram)。**线程安全**
// (quic-go Conn.SendDatagram 可并发调)→ N ASSOC 并发 send 零协调。
func (g *QuicHandle) SendDatagram(p []byte) error {
	return g.h.conn.SendDatagram(p)
}

// ReceiveDatagram 阻塞收一个 datagram(ctx 取消 / conn 关 → error;父 conn 直委派)。
// **conn 级唯一调用方** = UDP 池的 reader goroutine(quic-go 单 owner/conn;对照 Rust read_datagram 单 future/conn)。
func (g *QuicHandle) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return g.h.conn.ReceiveDatagram(ctx)
}

// MaxDatagramPayloadSize 单 datagram 明文上限(含 header;对照 quicConn.MaxDatagramPayloadSize)。
// quic-go 无直接方法 → 返 fallback 常量(已含 QUIC framing overhead);真实值仅 SendDatagram 失败时暴露。
func (g *QuicHandle) MaxDatagramPayloadSize() int {
	return quicDatagramBudget
}
