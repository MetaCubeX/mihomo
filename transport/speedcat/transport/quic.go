// quic.go —— QUIC dial arm(metacubex/quic-go + metacubex/tls)。对照 Rust proto-quic/src/transport.rs dial_quic。

package transport

import (
	"context"
	"fmt"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/quic-go"
	mtls "github.com/metacubex/tls"
)

// dialQUIC 建立 QUIC 连接 + open 一个 bidi stream,握手完成后返回 conn(exporter 取自父 conn)。
// 对照 Rust proto-quic dial_quic:quinn connect → open bidi stream。
// **TLS 握手在 quic.DialAddr 返回时已完成**(quic-go 阻塞至握手完;exporter 此时可取)。
//
// **L4 收尾(去重):** 建连主体抽 [dialQUICConn](池化路复用);本非池化路再 OpenStreamSync 一次性开
// stream(pooled=false → Close 关双,留 L2 单 stream/conn 语义;UDP/probe 走此)。
func dialQUIC(ctx context.Context, cfg Config) (Conn, error) {
	h, err := dialQUICConn(ctx, cfg)
	if err != nil {
		return nil, err
	}
	// open 一个 bidi stream 当字节流(quinn stream-id 即 demux;池化路开多 stream 复用同 conn)。
	stream, err := h.conn.OpenStreamSync(ctx)
	if err != nil {
		_ = h.conn.CloseWithError(quic.ApplicationErrorCode(0), "")
		return nil, fmt.Errorf("transport: quic open stream: %w", err)
	}
	return &quicConn{stream: stream, conn: h.conn, pooled: false}, nil
}

// quicConn 包一个 bidi stream(字节流)+ 父 QUIC conn(exporter 源)。
// 注意 metacubex/quic-go 的 Conn/Stream 都是**具体结构体**(非 interface),故用指针类型。
//
// **pooled(L4 收尾):** true = 此 conn 来自 QuicPool.OpenStream(池化,Close 只关 stream 留父 conn
// 给后续 stream 复用);false = 非池化(dialQUIC/UDP/probe,Close 关双)。对照 Rust 池化 QuicConnHandle::open_stream
// vs 非 pool dial_quic 的所有权分叉。
type quicConn struct {
	stream *quic.Stream
	conn   *quic.Conn
	pooled bool
}

func (q *quicConn) Read(p []byte) (int, error)  { return q.stream.Read(p) }
func (q *quicConn) Write(p []byte) (int, error) { return q.stream.Write(p) }

func (q *quicConn) Close() error {
	// 池化:只关 stream,留父 conn 给同 conn 其它 stream 复用(对照 Rust 池化 Close)。
	// 非池化:关 stream + 关父 conn(L2 单 stream/conn 语义)。
	if q.pooled {
		return q.stream.Close()
	}
	_ = q.stream.Close()
	return q.conn.CloseWithError(quic.ApplicationErrorCode(0), "")
}

// Exporter 取快路 exporter —— **从父 conn 取,非 stream**(stream 无 ConnectionState)。
// 委派 [quicConn.ExporterWithLabel](stream label);quic-go ConnectionState().TLS 是 metacubex/tls.
// ConnectionState(ExportKeyingMaterial 同 RFC 5705,指针 receiver,须先存本地变量取地址)。
// 对照 Rust proto-quic QuicConn::export_keying_material 委托 quinn。
func (q *quicConn) Exporter() ([crypto.KeyLen]byte, error) {
	return q.ExporterWithLabel(crypto.ExporterLabel)
}

// ExporterWithLabel 按指定 label 取 QUIC 父 conn 的 TLS exporter(L4 新增;datagram 路用
// crypto.UDPExporterLabel,与 stream crypto.ExporterLabel 域分离 → 独立密钥,ADR-009)。
// **从父 conn 取**(stream 无 ConnectionState),对照 Rust QuicConn::export_keying_material。
func (q *quicConn) ExporterWithLabel(label string) ([crypto.KeyLen]byte, error) {
	var out [crypto.KeyLen]byte
	tlsState := q.conn.ConnectionState().TLS
	b, err := tlsState.ExportKeyingMaterial(label, nil, crypto.KeyLen)
	if err != nil {
		return out, fmt.Errorf("transport: quic exporter: %w", err)
	}
	copy(out[:], b)
	return out, nil
}

// quicDatagramBudget 单 datagram 明文上限 fallback(L4;对照 Rust MVP_MAX_DATAGRAM_SIZE=1200)。
// quic-go 不暴露 max-size 方法(仅 SendDatagram 的 DatagramTooLargeError 携真实值)→ MVP 用此常量。
// 已含 QUIC framing overhead(gotcha #2);调用方扣 AEAD nonce/tag 得 §6.1 header+frag 预算。
// 探真实上限留收尾(SendDatagram 收 DatagramTooLargeError 反推)。
const quicDatagramBudget = 1200

// SupportsDatagrams 两端都开 datagram 才真(本地 EnableDatagrams + 对端 transport param)。
// 对照 Rust quinn conn:SendDatagram/RecvDatagram 双向支持。DialUDP 路径裁决用此判 datagram 臂。
func (q *quicConn) SupportsDatagrams() bool {
	s := q.conn.ConnectionState().SupportsDatagrams
	return s.Local && s.Remote
}

// SendDatagram 发一个不可靠 datagram(RFC 9221)。过大 → quic.DatagramTooLargeError。
// 对照 Rust QuicDatagramSink::send(委托 quinn send_dgram)。
func (q *quicConn) SendDatagram(p []byte) error {
	return q.conn.SendDatagram(p)
}

// ReceiveDatagram 阻塞收一个 datagram(ctx 取消 / conn 关 → error)。
// 对照 Rust per-conn reader task(conn.read_datagram → channel)。
func (q *quicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return q.conn.ReceiveDatagram(ctx)
}

// MaxDatagramPayloadSize 单 datagram 明文上限(含 §6.1 header;已含 QUIC framing overhead)。
// quic-go 无直接方法 → 返 fallback 常量;真实值仅在 SendDatagram 失败时暴露(DatagramTooLargeError)。
func (q *quicConn) MaxDatagramPayloadSize() int {
	return quicDatagramBudget
}

// quicTLSConfig 构造 metacubex/tls.Config(QUIC arm;字段兼容 stdlib crypto/tls.Config)。
// 与 [stdTLSConfig] 逻辑同(Rust 三分支),仅 tls 包不同(metacubex fork,API 一致)。
func quicTLSConfig(cfg Config) (*mtls.Config, error) {
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Host
	}
	tc := &mtls.Config{
		ServerName:         sni,
		MinVersion:         mtls.VersionTLS13,
		InsecureSkipVerify: cfg.Insecure,
	}
	if cfg.ALPN != "" {
		tc.NextProtos = []string{cfg.ALPN}
	}
	if cfg.CAFile != "" {
		pool, err := loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool // metacubex/tls 复用 stdlib crypto/x509.CertPool
	}
	return tc, nil
}
