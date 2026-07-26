// rawtcp.go —— 裸 TCP dial arm(L4 新增;对照 Rust proto-tls/src/transport.rs RawTcpConn)。
//
// **无 TLS exporter** —— Exporter()/ExporterWithLabel() 均返 ErrRawTCPNoExporter。handshake.Client 拿到
// exporter 探针失败 → 路由 disguiseClient(eph DH ClientHello/ServerHello + 双层 AEAD,NO_INNER_AEAD force
// OFF)→ 拨 Rust `server run --transport raw-tcp` 的 disguise_server。两端裸 TCP 配对,伪装路跨实现首通。
//
// # fail-safe(铁律)
//
// 裸 TCP **无传输层加密 / 无混淆**:TLS exporter = None,故无快路(0-RTT + 0 内层 AEAD);伪装路双层 AEAD
// 仍加密应用数据(对端错 PSK → 双层 AEAD 解密失败 → 连接断)。**仅 dev/测试/受控网络**;生产伪装用 21
// 单栈(tls_cert/forge_consistent)。这条 arm 的存在是为 L4 伪装路跨实现 e2e 兜底(解死结)。
//
// **panic-free**(被 mihomo import 的库:dial 错返 error)。

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
)

// ErrRawTCPNoExporter 裸 TCP 无 TLS exporter(命门:handshake 据此路由 disguiseClient;不静默退)。
var ErrRawTCPNoExporter = errors.New("transport/raw-tcp: 无 TLS exporter(伪装路,非快路)")

// dialRawTCP 建立裸 TCP 连接(无 TLS 握手;exporter 不可用 → 伪装路)。对照 Rust dial_raw_tcp。
// fail-safe:仅 dev/测试/受控网络(无传输层加密;生产用 21 单栈)。
func dialRawTCP(ctx context.Context, cfg Config) (Conn, error) {
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: raw-tcp dial %s: %w", addr, err)
	}
	return &RawTcpConn{c: raw}, nil
}

// RawTcpConn 包裸 net.Conn:字节流(io.ReadWriteCloser)+ exporter 探针恒失败(伪装路命门)。
// 对照 Rust RawTcpConn(impl AsyncRead/AsyncWrite + TransportConn{export_keying_material→None})。
type RawTcpConn struct{ c net.Conn }

func (r *RawTcpConn) Read(p []byte) (int, error)  { return r.c.Read(p) }
func (r *RawTcpConn) Write(p []byte) (int, error) { return r.c.Write(p) }
func (r *RawTcpConn) Close() error                { return r.c.Close() }

// Exporter 裸 TCP 无 exporter → ErrRawTCPNoExporter(handshake.Client 据此路由 disguiseClient)。
// 对照 Rust RawTcpConn::export_keying_material 返 None。
func (r *RawTcpConn) Exporter() ([crypto.KeyLen]byte, error) {
	return [crypto.KeyLen]byte{}, ErrRawTCPNoExporter
}

// ExporterWithLabel 同 [RawTcpConn.Exporter](裸 TCP 任何 label 都无 exporter;伪装路不取)。
func (r *RawTcpConn) ExporterWithLabel(string) ([crypto.KeyLen]byte, error) {
	return [crypto.KeyLen]byte{}, ErrRawTCPNoExporter
}
