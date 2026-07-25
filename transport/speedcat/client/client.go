// client.go —— speedcat 客户端 Client + Dial(TCP CONNECT;镜像 Rust Client::dial)。
//
// 流程:transport.Dial(ctx,cfg,kind) → handshake.Client(conn,psk,params) → Session → NewClientHalves →
// tx.EncryptFrameInto(TCPConnect, target.MarshalBinary())(占 ctr=0)→ Write → StreamConn。
// 首帧 TCPConnect 占 ctr=0,relay 数据帧从 ctr=1(对照 Rust,易踩坑 #5)。
//
// StreamConn 持 conn + tx + rx;[StreamConn.Relay] 把本地应用流(如 SOCKS5 客户端 TCP)与 speedcat conn
// 双向桥接(委托 [Relay])。方向:tx=C2S(发向 server)/ rx=S2C(收自 server),client 侧。
//
// **panic-free / 错误走 error**(被 mihomo import 的库,§6.1 对 Go 的等价约束)。

package client

import (
	"context"
	"errors"
	"io"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/mihomo/transport/speedcat/handshake"
	"github.com/metacubex/mihomo/transport/speedcat/transport"
	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// ErrDialFailed Dial/握手/发首帧任一失败(对照 Rust Client::dial 透出 proto Error)。
var ErrDialFailed = errors.New("client: dial 失败")

// Client speedcat 客户端:持传输配置 + kind + PSK + 握手参数,可重复 Dial 不同目标(对照 Rust Client)。
//
// **L4 收尾 · QUIC 池化:** kind=QUIC 时持 `quicPool`(N TCP Dial 复用 1 QUIC conn,省 N-1 RTT;对照 Rust
// Client 的 `Arc<QuicPool>`)+ `udpPool`(N UDP ASSOC 复用 1 QUIC conn,conn 级 reader 按 assoc_id demux;
// 对照 Rust 服务端 ConnDgRouter)。TCP/raw-tcp 不池化(各自 fresh conn)。两池物理隔离(TCP stream 池 vs
// UDP datagram 池,各拨各的 QUIC conn;对照 docs/09「池化与 UDP ASSOCIATE 干净分离」)。
type Client struct {
	cfg      transport.Config
	kind     transport.Kind
	psk      crypto.Psk
	params   handshake.Params
	quicPool *transport.QuicPool // kind=QUIC 时非 nil(TCP-CONNECT 池;L4 收尾 C)
	udpPool  *udpPool            // kind=QUIC 时非 nil(UDP ASSOC 池;L4 收尾 A)
}

// NewClient 构造客户端(cfg/kind 决定传输;psk 进握手;params 声明 caps + max_bw)。
// kind=QUIC 时惰性构造 quicPool + udpPool(L4 收尾;对照 Rust Client::new 建空池)。
func NewClient(cfg transport.Config, kind transport.Kind, psk crypto.Psk, params handshake.Params) *Client {
	// ADR-016 PADDING 塑形门控(与 Rust server/client 对称):TCP / raw-tcp(伪装路)offer CapPadding;
	// QUIC(速度路)不 offer。快路 client caps = 自身声明(0-RTT 无协商)→ 必须 kind != QUIC 时才 offer,
	// 否则 QUIC client 会误塑形。单一 chokepoint:所有 caller(socks5 binary / mihomo fork outbound)自动正确。
	if kind != transport.KindQUIC {
		params.Caps.SetPadding(true)
	}
	c := &Client{cfg: cfg, kind: kind, psk: psk, params: params}
	if kind == transport.KindQUIC {
		c.quicPool = transport.NewQuicPool(cfg)
		c.udpPool = newUDPClientPool(cfg)
	}
	return c
}

// Dial 建立 speedcat TCP 连接:transport.Dial → 握手(client)→ 发 TcpConnect(target)→ StreamConn。
// target = 期望服务端 dial 的目标(经 speedcat 代理)。ctx 支持取消/超时。
//
// **L4 收尾 · QUIC 池化分支:** kind=QUIC 时走 `c.quicPool.Dial`(N Dial 复用 1 QUIC conn,各开 1 stream;
// 省握手 → 对照 Rust `dial_or_reuse_quic`)。TCP/raw-tcp 仍 fresh `transport.Dial`。
func (c *Client) Dial(ctx context.Context, target wire.Addr) (*StreamConn, error) {
	var conn transport.Conn
	if c.kind == transport.KindQUIC && c.quicPool != nil {
		// 池化:复用/单-flight 建 1 QUIC conn,开 1 stream(pooled=true → Close 只关 stream,父 conn 续命)。
		var err error
		conn, err = c.quicPool.Dial(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		conn, err = transport.Dial(ctx, c.cfg, c.kind)
		if err != nil {
			return nil, err
		}
	}
	sess, err := handshake.Client(conn, c.psk, c.params)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	tx, rx := NewClientHalves(sess)

	// 首帧 TCPConnect 占 ctr=0(易踩坑 #5):target.Addr 编码为帧体(对照 Rust target.encode())。
	targetBytes, err := target.MarshalBinary()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	var frame []byte
	if _, err := tx.EncryptFrameInto(wire.FrameTCPConnect, targetBytes, &frame); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write(frame); err != nil {
		_ = conn.Close()
		return nil, err
	}
	// tx/rx 持可变状态(ctr / highest),StreamConn 持指针 —— Relay 双 goroutine 各持一份指针并发跑。
	return &StreamConn{conn: conn, tx: &tx, rx: &rx}, nil
}

// StreamConn 一条已建连的 speedcat TCP 流(持 transport.Conn + 加密/解密两半)。
// 调用 [StreamConn.Relay] 把它与本地应用流双向桥接;用完调 [StreamConn.Close]。
type StreamConn struct {
	conn transport.Conn
	tx   *SessionTx
	rx   *SessionRx
}

// Relay 把本地应用流 local(如 SOCKS5 客户端 net.Conn)与本 speedcat conn 双向桥接(委托 [Relay])。
// 阻塞至两向结束;返回首个非良性错误。local 须实现 io.ReadWriteCloser(net.Conn 满足)。
func (s *StreamConn) Relay(local io.ReadWriteCloser) error {
	return Relay(s.tx, s.rx, s.conn, local)
}

// Close 关闭底层 speedcat conn(含 QUIC 父 conn / TLS 流)。
func (s *StreamConn) Close() error { return s.conn.Close() }
