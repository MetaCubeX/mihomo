// udp.go —— speedcat 客户端 UDP 隧道(DialUDP + UdpTunnel,镜像 Rust speedcat-client/src/lib.rs:361 dial_udp;
// 两臂并发模型对照 run_udp_datagram_tunnel / run_udp_stream_tunnel)。
//
// # 流程
//
// DialUDP = **按 kind 分臂** → handshake.Client → 发 UdpAssociate(0x04)首帧建关联(占 ctr=0,与 TCP Dial 的
// TCPConnect 对称,只换首帧类型)→ spawn relay → 返回 UdpTunnel(仅持 channel,轻量)。
//
// # 分臂(L4 收尾 A:QUIC 走池化 datagram;TCP/raw-tcp 走流隧道)
//
//   - **QUIC 臂**(pooled datagram,L4 收尾 A):`c.udpPool.get()` 取/建 **1 共享 QUIC conn**(N ASSOC 复用,
//     省 N-1 握手 RTT)→ allocAssoc 分配单调 assoc_id → `handle.OpenStream` 开握手流 → handshake →
//     发 `UdpAssociate(assocID, target)` → `runPooledDatagramRelay`(共享 conn 级 handle + dc,conn 级单 reader
//     按 assoc_id demux;对照 Rust 服务端 ConnDgRouter)。**ADR-009 随机 nonce AEAD,无 ctr/无重放,dc 共享零协调**。
//   - **流隧道臂**(TCP / raw-tcp fallback):fresh `transport.Dial` → `UdpData`(0x05)帧复用 Session ctr AEAD
//     (02 §3,与 TcpData 同层);TCP 可靠按序 + u16 len cap → 单帧一报文不分片。
//
// # UdpTunnel 并发(channel 解耦,非 Rust select!)
//
// Rust 用 `tokio::select!` 单 task 多路;Go 用 goroutine + channel:
//   - `cmd` chan(SOCKS5→目标,出向)/ `reply` chan(目标→SOCKS5,入向)/ `done` chan(外部 Close 信号)。
//   - 出向由主循环读 cmd;入向由 reader/reassembly goroutine(逐 arm 不同)。任一方退出 → 关 conn / cancel ctx → 另一方退。
//
// **关闭语义:** UdpTunnel.Close 关 `done` → task 各 select 命中 done 退 → defer 关 conn + close(reply)。
// RecvFrom 见 reply 关闭 → 返 ErrTunnelClosed(EOF 语义);SendTo 见 done → 返 ErrTunnelClosed。
//
// # 热路径(ADR-005)
//
// TCP relay pump 是 ADR-005 零成本约束区;UDP reassembly / datagram seal 属 per-UDP-packet 段(UDP 天然
// 较 TCP 低吞吐,reassembly 单 goroutine 持有,无锁)。MVP 先正确(per-packet alloc),零拷贝留收尾。
// **AEAD/decode 内禁日志**(§5.3)。**panic-free**(被 mihomo import 的库:错返 error)。
//
// **assoc_id:** QUIC 臂经 `udpConnState.allocAssoc` 单调分配(起点 1;L4 收尾 A,N ASSOC/conn);流隧道臂
// 固定 1(单 ASSOC/fresh conn,无 demux 需要)。

package client

import (
	"context"
	"errors"
	"sync"

	"github.com/metacubex/mihomo/transport/speedcat/handshake"
	"github.com/metacubex/mihomo/transport/speedcat/transport"
	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// ErrTunnelClosed 隧道已关(外部 Close / 对端关 / conn 断)。RecvFrom/SendTo 见此 = EOF 语义。
var ErrTunnelClosed = errors.New("client/udp: 隧道已关闭")

// udpCmdBuf cmd channel 缓冲(出向;对照 Rust mpsc::channel(64))。
const udpCmdBuf = 64

// UdpPacket 一个 UDP 报文(addr = 目标/源 + payload)。经 cmd/reply channel 在 UdpTunnel 与 task 间流转。
type UdpPacket struct {
	Addr wire.Addr
	Data []byte
}

// UdpTunnel speedcat UDP 关联句柄(仅持 channel,轻量;对照 Rust UdpTunnel)。
// 调用方:SendTo 发报文 / RecvFrom 收报文 / Close 终结关联。goroutine 安全(channel 串行化)。
type UdpTunnel struct {
	cmd       chan UdpPacket
	reply     chan UdpPacket
	done      chan struct{}
	closeOnce sync.Once
}

// SendTo 发一个 UDP 报文到 addr(出向:本地应用 → 隧道 → 服务端 → 目标)。
// 阻塞至 cmd 有空位 / 隧道关 / ctx 取消。隧道关 → ErrTunnelClosed(对照 Rust UdpTunnel::send Err)。
func (t *UdpTunnel) SendTo(ctx context.Context, addr wire.Addr, data []byte) error {
	select {
	case t.cmd <- UdpPacket{Addr: addr, Data: data}:
		return nil
	case <-t.done:
		return ErrTunnelClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RecvFrom 收一个 UDP 报文(入向:目标 → 服务端 → 隧道 → 本地应用),返回 (源 addr, payload)。
// 隧道关(对端关 / task 退)→ ErrTunnelClosed(EOF 语义,对照 Rust UdpTunnel::recv Err)。
func (t *UdpTunnel) RecvFrom(ctx context.Context) (wire.Addr, []byte, error) {
	select {
	case p, ok := <-t.reply:
		if !ok {
			return wire.Addr{}, nil, ErrTunnelClosed // reply 关 = reader 退 = 隧道关
		}
		return p.Addr, p.Data, nil
	case <-ctx.Done():
		return wire.Addr{}, nil, ctx.Err()
	}
}

// Close 终结 UDP 关联(关 done → task 各 select 退 → 关 conn)。多次调幂等(sync.Once)。
func (t *UdpTunnel) Close() error {
	t.closeOnce.Do(func() { close(t.done) })
	return nil
}

// DialUDP dial + handshake + 发 UdpAssociate 首帧 → 按 kind 分臂 spawn relay → UdpTunnel。
// 与 [Client.Dial](TCP CONNECT)对称,只换首帧类型(0x04 UdpAssociate 建关联)。
//
// **分臂(L4 收尾 A):**
//   - QUIC:`c.udpPool.get()` 取/建 **1 共享 QUIC conn**(N ASSOC 复用)→ allocAssoc 分 assoc_id → OpenStream
//     握手 → 发 `UdpAssociate(assocID,target)` → `runPooledDatagramRelay`(共享 conn 级 handle + dc,
//     conn 级单 reader 按 assoc_id demux;对照 Rust 服务端 ConnDgRouter)。
//   - TCP/raw-tcp:fresh `transport.Dial` → `runStreamTunnel`(单 ASSOC,assoc_id 固定 1,无 demux)。
//
// 两臂对外统一 UdpTunnel(调用方零分支)。conn/stream 所有权转 relay(续命 QUIC conn / TCP 流);relay 退则关。
//
// target 进 UdpAssociate 帧(服务端 datagram 路不据此路由 —— 每报文 §6.1 header 自带目标;仅元信息)。
func (c *Client) DialUDP(ctx context.Context, target wire.Addr) (*UdpTunnel, error) {
	cmd := make(chan UdpPacket, udpCmdBuf)
	reply := make(chan UdpPacket, udpCmdBuf)
	tun := &UdpTunnel{cmd: cmd, reply: reply, done: make(chan struct{})}

	if c.kind == transport.KindQUIC && c.udpPool != nil {
		// QUIC pooled datagram 臂(L4 收尾 A):1 共享 QUIC conn 承 N ASSOC(省 N-1 握手 RTT)。
		state, err := c.udpPool.get(ctx)
		if err != nil {
			return nil, err
		}
		assocID := state.allocAssoc() // 单调 assoc_id(conn 内唯一;两端 router 据之分发)。
		// 开握手流(pooled=true → Close 只关 stream,留父 conn 给池复用)。handshake(fast/disguise)在此流跑。
		streamConn, err := state.handle.OpenStream(ctx)
		if err != nil {
			return nil, err
		}
		sess, err := handshake.Client(streamConn, c.psk, c.params)
		if err != nil {
			_ = streamConn.Close()
			return nil, err
		}
		tx, _ := NewClientHalves(sess) // rx(datagram 路不用)弃用:datagram 报文走共享 dc,不经 session AEAD。

		// 首帧 UdpAssociate 占 ctr=0(易踩坑 #5;与 TCP Dial 的 TCPConnect 对称)。带 assoc_id 供 server 注册 router。
		body, err := EncodeUDPAssociate(assocID, target)
		if err != nil {
			_ = streamConn.Close()
			return nil, err
		}
		var frame []byte
		if _, err := tx.EncryptFrameInto(wire.FrameUDPAssociate, body, &frame); err != nil {
			_ = streamConn.Close()
			return nil, err
		}
		if _, err := streamConn.Write(frame); err != nil {
			_ = streamConn.Close()
			return nil, err
		}
		// streamConn 续命供 server 知 ASSOC 活(relay 退时关 → server 见 stream 关 = ASSOC 结束)。
		go runPooledDatagramRelay(streamConn, state.handle, state.dc, state, assocID, state.maxPlain, cmd, reply, tun.done)
		return tun, nil
	}

	// 流隧道臂(TCP / raw-tcp):fresh conn,单 ASSOC(assoc_id 固定 1,无 demux)。
	conn, err := transport.Dial(ctx, c.cfg, c.kind)
	if err != nil {
		return nil, err
	}
	sess, err := handshake.Client(conn, c.psk, c.params)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	tx, rx := NewClientHalves(sess)

	const assocID uint16 = 1 // 流隧道单 ASSOC/fresh conn;关联内唯一(对照 Rust)。
	body, err := EncodeUDPAssociate(assocID, target)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	var frame []byte
	if _, err := tx.EncryptFrameInto(wire.FrameUDPAssociate, body, &frame); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write(frame); err != nil {
		_ = conn.Close()
		return nil, err
	}
	go runStreamTunnel(conn, &tx, &rx, cmd, reply, tun.done)
	return tun, nil
}

// runStreamTunnel 流隧道臂 relay(TCP fallback)。UdpData(0x05)帧复用 Session ctr AEAD(02 §3),
// 单帧一报文(TCP 可靠按序 + u16 len cap,不分片)。对照 Rust run_udp_stream_tunnel。
//
// writer goroutine(cmd → EncodeUDPData → EncryptFrameInto(UdpData)→ Write)+ reader goroutine
// (ReadFrame → DecryptFrame → DecodeUDPData → reply)。net.Conn 读写半并发安全;tx 归 writer / rx 归 reader,
// 无共享可变状态。任一退 → 关 conn(kick 对方)+ close(stop)→ 两者皆退,wg.Wait 返回。
//
// 退出路径:① 外部 done → writer 退 → defer conn.Close → reader ReadFrame 报错退;
// ② 对端关 → reader ReadFrame 报错退 → defer close(stop) → writer 退;③ writer Write 报错 → writer 退 → 关 conn → reader 退。
func runStreamTunnel(
	conn transport.Conn,
	tx *SessionTx,
	rx *SessionRx,
	cmd <-chan UdpPacket,
	reply chan<- UdpPacket,
	done <-chan struct{},
) {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// writer:出向。退 → defer conn.Close(kick reader 的 ReadFrame)。
	go func() {
		defer wg.Done()
		defer conn.Close()
		var frame []byte
		for {
			select {
			case p, ok := <-cmd:
				if !ok {
					return
				}
				body, err := EncodeUDPData(p.Addr, p.Data)
				if err != nil {
					continue
				}
				frame = frame[:0]
				if _, err := tx.EncryptFrameInto(wire.FrameUDPData, body, &frame); err != nil {
					continue
				}
				if _, err := conn.Write(frame); err != nil {
					return // conn 断 → 关联结束。
				}
			case <-stop:
				return
			case <-done:
				return
			}
		}
	}()

	// reader:入向。退 → defer close(stop)(kick writer)+ defer close(reply)。
	go func() {
		defer wg.Done()
		defer close(stop)
		defer close(reply)
		var out []byte
		for {
			hdr, body, err := ReadFrame(conn)
			if err != nil {
				return // EOF / 读错 → 关联结束。
			}
			ftype, payload, err := rx.DecryptFrame(hdr, body, &out)
			if err != nil {
				return // AEAD/重放 → fail-loud 杀关联(TCP 流错 = 对端坏,非丢包)。
			}
			if ftype != wire.FrameUDPData {
				continue // 非 UdpData 帧关联期到达:忽略(对照 Rust)。
			}
			addr, data, derr := DecodeUDPData(payload)
			if derr != nil {
				continue
			}
			select {
			case reply <- UdpPacket{Addr: addr, Data: data}:
			case <-stop:
				return
			}
		}
	}()

	wg.Wait()
}
