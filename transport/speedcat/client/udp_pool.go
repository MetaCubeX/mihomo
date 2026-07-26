// udp_pool.go —— 客户端 UDP 池 + N-ASSOC/conn datagram demux(L4 收尾 A;镜像 Rust 服务端
// ConnDgRouter —— proto-quic/src/datagram_router.rs。
//
// # 解决什么(兑现 L4 收尾 A 客户端侧)
//
// Stage 2 单 ASSOC/QUIC-conn:`DialUDP` 每 ASSOC 拨一条 fresh QUIC conn(含独立 reader)。N ASSOC = N conn +
// N 握手(N RTT),与 (1-conn-N-stream,省 N-1 RTT)背道。本池让 **1 QUIC conn 承 N ASSOC**:
//   - 池持 1 `*transport.QuicHandle`(conn 级句柄:OpenStream 开 N 握手流 + conn 级 datagram reader/sender);
//   - conn 级**单** reader goroutine(`ReceiveDatagram` 单 owner/conn 语义,对照 Rust read_datagram 单 future/conn)
//     把收到的 datagram **按 header.AssocID 分发**给各自 ASSOC 的 inbound channel;
//   - 各 ASSOC 经 [`udpConnState.register`] 领独占 inbound channel,自跑 [`ReassemblyBuffer`] 重组 + sender 循环。
//
// # 与 TCP-CONNECT 池(QuicPool)的关系:物理隔离
//
// TCP CONNECT 走 [`transport.QuicPool`](stream 池,**不** spawn datagram reader);UDP ASSOC 走本池(conn 级
// QuicHandle + datagram reader)。两者各拨各的 QUIC conn(同时用 TCP+UDP = 2 conn,可接受;对照 docs/09
// 「池化与 UDP ASSOCIATE 干净分离」+ Rust UDP 非 pool 每 ASSOC 1 conn)。本池只管 UDP ASSOC。
//
// # register race(datagram 早于 register 到达)
//
// 客户端发 `UdpAssociate`(stream 帧,带 assoc_id)后立即发 datagram(conn 通道);datagram 可能**先于**
// server 注册 / 本端 register 到达 → 未命中 route。解(对照 Rust pending):reader 给未注册 assoc_id 缓冲进
// `pending`(cap 8,满丢最旧),`register` 时 drain。**单 `sync.Mutex`** 把 reader 的(查 routes + push pending)
// 与 register 的(drain pending + insert route)做成相对彼此原子的临界区 → check-then-push 与 insert-then-drain
// 不交错,**不丢包**。
//
// # 前置不变量(并发 send 零协调)
//
// `DatagramCipher` 无 ctr / 无重放 / immutable → N ASSOC 共享一份 dc,并发 Seal 零锁零协调;quic-go
// `Conn.SendDatagram` 内部 thread-safe channel → N ASSOC 并发 send 经共享 `handle.SendDatagram` 无锁。
//
// # 关闭语义 / conn 死亡级联
//
// `udpConnState.closed`(chan)在 reader 退(`ReceiveDatagram` 错 = conn 死)时关一次 → 所有 ASSOC 的 sender /
// reassembly goroutine 经 `select` 命中 `<-closed` 退。外部 Close(`UdpTunnel.done`)关单条 ASSOC;conn 死亡关
// 全部。reassembly goroutine 拥有 `close(reply)`(单 sender → 无 send-on-closed),对照 `runStreamTunnel`。
//
// # 冷热路径
//
// 拨 conn / 握手 / register / 分派 = 冷路径(连接生命周期事件);reader 的 dc.Open 是 datagram 路固有成本
// (非本池引入)。锁只在分派/register 瞬态临界区持有,reassembly/sender 各持独占状态无锁。**禁每 datagram 日志**。
//
// dev 限制:pending cap 8 / inbound chan 64 是保守默认(UDP 暴发容忍);assoc_id 单调分配器(u16,起点 1)。

package client

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/mihomo/transport/speedcat/transport"
)

// pendingCap 未注册 assoc_id 的 datagram 缓冲上限(对照 Rust ConnDgRouter::PENDING_CAP=8)。
// 防无界增长被未注册/恶意流量打爆;满丢最旧(UDP 允许丢)。
const pendingCap = 8

// assocChan per-ASSOC inbound channel 容量(reader → 该 ASSOC reassembly;对照 Rust ASSOC_CHAN=64)。
const assocChan = 64

// errDupAssoc 重复注册同一 assoc_id(fail-loud;allocAssoc 单调 → 理论不发生,除非 u16 wrapping 碰撞)。
var errDupAssoc = errors.New("client/udp: assoc_id 重复注册")

// inboundFrag reader 投给某 ASSOC 的一笔分片(已解密 + 解码 header;reassembly goroutine 据此 Insert)。
type inboundFrag struct {
	h    DatagramHeader // header(含 AssocID / frag 元信息;首片带 Addr)
	frag []byte         // 该片 payload
	now  time.Time      // 到达时间(GC 节流 + Insert created 用)
}

// udpConnState 一条已建连 QUIC conn 的 UDP 池态:conn 级 handle + 共享 dc + per-assoc routes/pending +
// conn 级 reader goroutine。对照 Rust ConnDgRouter(conn 级单 reader + routes + pending)。
type udpConnState struct {
	handle   *transport.QuicHandle // conn 级句柄(OpenStream 开握手流 + conn 级 datagram reader/sender)
	dc       *DatagramCipher       // 共享 AEAD(immutable;N ASSOC 并发 Seal 零协调)
	maxPlain int                   // 单 datagram 明文上限(含 header;扣 AEAD nonce/tag)

	// routes + pending 在同一把锁下 → reader 的 dispatch 与 relay 的 register 相对彼此原子(解 race)。
	mu        sync.Mutex
	routes    map[uint16]chan inboundFrag // 已注册 ASSOC:assoc_id → 该 ASSOC 的 inbound channel
	pending   map[uint16][]inboundFrag    // 未注册 assoc_id 的积压(cap pendingCap,满丢最旧)
	nextAssoc uint16                      // 单调 assoc_id 分配器(起点 1;u16 wrapping 碰撞 → register fail-loud)

	closed    chan struct{} // reader 退(conn 死)时关一次 → 所有 ASSOC goroutine 经 select 退
	closeOnce sync.Once
}

// isDead conn 已死(reader 退 / handle 不活)→ 池慢路重 dial 判据。handle nil(测试态)→ 仅看 closed。
func (s *udpConnState) isDead() bool {
	select {
	case <-s.closed:
		return true
	default:
	}
	return s.handle != nil && !s.handle.IsAlive()
}

// markClosed 关 closed 一次(reader 退时调;幂等)。→ 所有 ASSOC 的 sender/reassembly 经 `<-closed` 退。
func (s *udpConnState) markClosed() {
	s.closeOnce.Do(func() { close(s.closed) })
}

// readerLoop conn 级 datagram reader(唯一 ReceiveDatagram 调用方;对照 Rust router_loop)。
// ReceiveDatagram → dc.Open → DecodeDatagramHeader → dispatch(按 AssocID 投 route / 缓冲 pending)。
// conn 关 / 读错 → 退 + markClosed(级联所有 ASSOC)。解密/解码失败 → 丢该 datagram(UDP 允许丢/噪)。
func (s *udpConnState) readerLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer s.markClosed() // 退时关 closed → 所有 ASSOC 退(级联)。
	for {
		wireData, err := s.handle.ReceiveDatagram(ctx)
		if err != nil {
			return // ctx 取消 / conn 关 → 关联结束(reader 退)。
		}
		now := time.Now()
		pt, err := s.dc.Open(wireData)
		if err != nil {
			continue // 解密失败 → 丢该 datagram(不杀关联;UDP 允许丢/噪)。
		}
		h, frag, err := DecodeDatagramHeader(pt)
		if err != nil {
			continue // header 畸形 → 丢(不杀关联)。
		}
		s.dispatch(h, frag, now)
	}
}

// dispatch 处理一笔已解密分片(对照 Rust dispatch_one):命中 route 直投(满丢)/ 未命中缓冲 pending(cap 8,
// 满丢最旧)。**纯同步临界区**(查 routes / send / push pending),guard 在函数末尾自然 drop(无 await/无 Go 阻塞)。
func (s *udpConnState) dispatch(h DatagramHeader, frag []byte, now time.Time) {
	f := inboundFrag{h: h, frag: frag, now: now}
	s.mu.Lock()
	if ch, ok := s.routes[h.AssocID]; ok {
		s.mu.Unlock()
		// 命中已注册 ASSOC:非阻塞投(满 → 丢该 datagram,UDP 语义;对照 Rust try_send)。
		select {
		case ch <- f:
		default:
		}
		return
	}
	// 未注册(datagram 早于 register / 未知 assoc_id):缓冲 pending(cap 8,满丢最旧)。
	p := s.pending[h.AssocID]
	if len(p) >= pendingCap {
		// 满 → 丢最旧(in-place 左移,不 alloc;对照 Rust VecDeque::pop_front)。
		copy(p, p[1:])
		p[pendingCap-1] = f
	} else {
		s.pending[h.AssocID] = append(p, f)
	}
	s.mu.Unlock()
}

// register 注册一个 ASSOC:返该 ASSOC 专用的 inbound channel。drain pending 中该 id 积压(解 race);
// 重复注册(fail-loud)→ error。对照 Rust register_inner。
func (s *udpConnState) register(id uint16) (chan inboundFrag, error) {
	ch := make(chan inboundFrag, assocChan)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.routes[id]; ok {
		// 重复注册:fail-loud(协议违规 / u16 wrapping 碰撞)→ 不静默覆盖既有 route。
		return nil, errDupAssoc
	}
	// drain pending 中该 id 的积压(非阻塞投;满 → 丢该条,UDP 语义)。insert route 后 reader 命中直投。
	for _, f := range s.pending[id] {
		select {
		case ch <- f:
		default:
		}
	}
	delete(s.pending, id)
	s.routes[id] = ch
	return ch, nil
}

// unregister 注销 ASSOC(从 routes 删;relay 退时调,reader 不再向其分派)。不关 inbound(reader 是唯一发送方;
// channel 随 relay goroutine 退而 GC)。
func (s *udpConnState) unregister(id uint16) {
	s.mu.Lock()
	delete(s.routes, id)
	s.mu.Unlock()
}

// allocAssoc 分配一个单调 assoc_id(u16,起点 1)。对照 Rust「每 conn 单调自增」。wrapping 碰撞(65536 并发
// ASSOC)→ register fail-loud(理论不可能)。
func (s *udpConnState) allocAssoc() uint16 {
	s.mu.Lock()
	id := s.nextAssoc
	s.nextAssoc++
	s.mu.Unlock()
	return id
}

// udpPool 客户端 UDP 池:至多持 1 udpConnState(N UDP ASSOC 复用 1 QUIC conn;对照 Rust 客户端池前提)。
// 单 flight(同 QuicPool 语义):快路复用 / 慢路持锁贯穿 dial。
type udpPool struct {
	cfg transport.Config
	mu  sync.Mutex
	// state 当前 conn 态(nil / isDead → 慢路重 dial)。至多 1。
	state *udpConnState
	// dials 慢路成功建连计数(client 侧 conn-count 可观测;对照 Rust QuicListener::conn_count)。
	// 单 flight → 冷启 N 并发首 dial 序列化 → 此值 = 1 即「N ASSOC 收敛到 1 conn」铁证(跨实现 e2e 用)。
	dials atomic.Uint64
	// dialState 建 conn 态的函数(生产 = 真拨 QUIC + 派 dc + spawn reader;测试注入替身验编排)。
	dialState func(ctx context.Context) (*udpConnState, error)
}

// newUDPClientPool 构造 UDP 池(dialState = 真拨 QUIC;池懒 dial,DialUDP 才建连)。
func newUDPClientPool(cfg transport.Config) *udpPool {
	p := &udpPool{cfg: cfg}
	p.dialState = p.dialStateReal
	return p
}

// dialStateReal 真拨一条 QUIC conn → conn 级 handle → 派共享 dc + spawn reader → udpConnState(生产路径)。
func (p *udpPool) dialStateReal(ctx context.Context) (*udpConnState, error) {
	handle, err := transport.DialQuicHandle(ctx, p.cfg)
	if err != nil {
		return nil, err
	}
	// DatagramCipher 从 conn 级 exporter 派生(label=UDPExporterLabel,与 stream 域分离 → 独立 32B key)。
	// 与 server ConnDgRouter 同 QUIC TLS session → 同 exporter → 同 key(对称)。
	key, err := handle.ExporterWithLabel(crypto.UDPExporterLabel)
	if err != nil {
		_ = handle.Close()
		return nil, err
	}
	if !handle.SupportsDatagrams() {
		// fail-safe:两端须 EnableDatagrams;不支持 → 拒(对照 Rust ConnDgRouter::new 无 exporter → datagram 关)。
		_ = handle.Close()
		return nil, errors.New("client/udp: QUIC conn 不支持 datagram(两端须 EnableDatagrams)")
	}
	dc := NewDatagramCipherFromKey(key)
	// maxPlain = 单 datagram 明文上限(含 header;扣 AEAD nonce 12 + tag 16;quicDatagramBudget 已含 QUIC framing)。
	maxPlain := handle.MaxDatagramPayloadSize() - crypto.NonceLen - crypto.TagLen
	s := &udpConnState{
		handle:    handle,
		dc:        dc,
		maxPlain:  maxPlain,
		routes:    make(map[uint16]chan inboundFrag),
		pending:   make(map[uint16][]inboundFrag),
		nextAssoc: 1, // 起点 1(避开 0;对照测试约定 assoc 1)。
		closed:    make(chan struct{}),
	}
	go s.readerLoop() // conn 级单 reader(独占 ReceiveDatagram)。
	return s, nil
}

// get 取 conn 态(快路复用 / 慢路 single-flight dial)。对照 QuicPool.Dial + Rust dial_or_reuse_quic。
// 返回的 state 若随后死,调用方(DialUDP)的 relay 经 SendDatagram/ReceiveDatagram 错自退;下次 get 重 dial。
func (p *udpPool) get(ctx context.Context) (*udpConnState, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		// 快路:锁内判活取 state → 锁外返(并发复用不序列化)。
		p.mu.Lock()
		if s := p.state; s != nil && !s.isDead() {
			p.mu.Unlock()
			return s, nil
		}
		// 慢路:持锁贯穿 dial(冷启 N 并发首 dial 排队 → 只建 1 conn 无 orphan;对照 Rust 持锁贯穿 dial_quic_conn)。
		s, err := p.dialState(ctx)
		if err != nil {
			p.mu.Unlock()
			return nil, err
		}
		p.dials.Add(1) // 建连成功计数(单 flight → 冷启 = 1;跨实现 e2e 用此断言 N ASSOC 1 conn)。
		p.state = s
		p.mu.Unlock()
		return s, nil
	}
}

// Dials 返回本池已成功建立的 QUIC conn 数(client 侧 conn-count 可观测)。池化语义:N DialUDP 收敛到
// 1 conn → 此值应 = 1(冷启并发)。对照 transport.QuicPool.Dials。
func (p *udpPool) Dials() uint64 { return p.dials.Load() }

// runPooledDatagramRelay pooled datagram 臂 relay(L4 收尾 A;QUIC)。镜像 runDatagramTunnel 但:
//   - **共享** conn 级 handle(sender 经 handle.SendDatagram 并发安全)+ 共享 dc(N ASSOC 零协调);
//   - inbound 分片来自 conn 级 reader(按 AssocID 分发到本 ASSOC 的 inbound channel),非自起 reader;
//   - 各 ASSOC 自跑 ReassemblyBuffer(单 owner无锁,对照 runDatagramTunnel 的 reader goroutine)。
//
// 并发模型(对照 runStreamTunnel:双 goroutine + wg):sender goroutine(出向)+ reassembly goroutine(入向,
// 拥有 close(reply));任一退 → close(stop)kick 对方 → wg.Wait → 关握手流(ASSOC 结束信号)+ unregister。
// conn 死亡(state.closed)→ 两 goroutine 经 select 同时退。reassembly 唯一发 reply → 无 send-on-closed。
func runPooledDatagramRelay(
	streamConn transport.Conn, // 握手流(kept alive 供 server 知 ASSOC 活;Close 信号 ASSOC 结束;pooled → 只关 stream)
	handle *transport.QuicHandle, // 共享 conn 级句柄(sender 经 handle.SendDatagram)
	dc *DatagramCipher, // 共享 AEAD(immutable)
	state *udpConnState, // 池态(register/unregister conn 级 reader 的路由)
	assocID uint16,
	maxPlain int,
	cmd <-chan UdpPacket,
	reply chan<- UdpPacket,
	done <-chan struct{},
) {
	inbound, err := state.register(assocID)
	if err != nil {
		// 重复 assoc(allocAssoc 单调 → 理论不发生)→ fail-loud:关 reply + 握手流,返(关联失败)。
		_ = streamConn.Close()
		close(reply)
		return
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// sender goroutine:出向(cmd → Fragment → dc.Seal → handle.SendDatagram)。退 → close(stop)kick reassembly。
	go func() {
		defer wg.Done()
		defer close(stop)
		var pktID uint16 // 关联内单调(u16 自然 wrapping;65536 并发未决包才碰撞,不可能)。
		for {
			select {
			case p, ok := <-cmd:
				if !ok {
					return // cmd 关(保留分支;现用 done 关)→ 关联结束。
				}
				frags, ferr := Fragment(assocID, pktID, &p.Addr, p.Data, maxPlain)
				pktID++
				if ferr != nil {
					continue // max_plain 异常 → 丢该包(对照 Rust)。
				}
				for _, fr := range frags {
					w, werr := fr.H.EncodeWithPayload(fr.Payload)
					if werr != nil {
						continue
					}
					sealed, serr := dc.Seal(w)
					if serr != nil {
						return // AEAD 错 = fatal → 关联结束。
					}
					// 共享 handle.SendDatagram(quic-go thread-safe → N ASSOC 并发 send 零锁)。
					if err := handle.SendDatagram(sealed); err != nil {
						return // conn 关 / DatagramTooLarge → 关联结束(conn 死 reader 也会 markClosed)。
					}
				}
			case <-done:
				return // 外部 Close(单 ASSOC)→ 关联结束。
			case <-state.closed:
				return // conn 死(reader 退)→ 关联结束。
			}
		}
	}()

	// reassembly goroutine:入向(inbound → ReassemblyBuffer → reply)。拥有 close(reply)(唯一 reply 发送方)。
	go func() {
		defer wg.Done()
		defer close(reply) // reader 退 → 关 reply(RecvFrom 见 EOF;唯一发送方 → 无 send-on-closed)。
		rb := NewReassemblyBuffer()
		lastGc := time.Now()
		for {
			select {
			case f, ok := <-inbound:
				if !ok {
					return // inbound 关(理论不发生;reader 不关 inbound)→ 退。
				}
				// inline GC(按报文节流;空闲无累积 → 不需独立 ticker;对照 runDatagramTunnel)。
				if f.now.Sub(lastGc) >= GcInterval {
					rb.GC(f.now, GcLifetime)
					lastGc = f.now
				}
				addr, payload, complete, ierr := rb.Insert(f.h, f.frag, f.now)
				if ierr != nil || !complete || addr == nil {
					continue // 校验失败 / 未集齐 → 丢(不杀关联)。
				}
				select {
				case reply <- UdpPacket{Addr: *addr, Data: payload}:
				case <-stop:
					return
				case <-done:
					return
				case <-state.closed:
					return
				}
			case <-stop:
				return // sender 退 → kick。
			case <-done:
				return
			case <-state.closed:
				return
			}
		}
	}()

	wg.Wait()
	_ = streamConn.Close()    // 关握手流 → server 见 stream 关 = ASSOC 结束(pooled → 只关 stream,留父 conn)。
	state.unregister(assocID) // 清 route(reader 不再向死 ASSOC 分派;防 orphan inbound 积压)。
}
