// tls.go —— TCP+TLS 1.3 dial arm(**uTLS Chrome 指纹**,反库级 JA3/JA4;internal/25 M2 / ADR-017 P2)。
// 对照 Rust proto-tls/src/transport.rs dial_tls(rustls 无法做完整 ClientHello 模仿 → Rust 客户端仍库级指纹)。

package transport

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	utls "github.com/metacubex/utls"
)

// dialTCP 建立 TCP + TLS 1.3 连接;**ClientHello 用 uTLS Chrome 指纹**。握手完成后返回 conn(exporter 可取)。
func dialTCP(ctx context.Context, cfg Config) (Conn, error) {
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: tcp dial %s: %w", addr, err)
	}
	tlsCfg, err := utlsClientConfig(cfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	// uTLS Chrome 指纹:UClient 用 HelloChrome_Auto(Chrome 133)的 ClientHello 形态 → JA3/JA4 与真 Chrome
	// 一致,消除「自托管小 TLS server」库级指纹(internal/25 M2)。metacubex/utls TLS 1.3 握手正常填 ekm
	// 闭包(handshake_client_tls13.go)→ ConnectionState().ExportKeyingMaterial 可取快路 exporter(e2e 已验)。
	c := utls.UClient(raw, tlsCfg, utls.HelloChrome_Auto)
	if err := c.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("transport: utls handshake %s: %w", addr, err)
	}
	// ★ exporter 解锁(承重):Chrome preset 的 renegotiation_info 扩展经 writeToUConn 把
	// config.Renegotiation 设成 RenegotiateOnceAsClient(utls u_tls_extensions.go:1691)→ 触发
	// ExportKeyingMaterial 的「renegotiation enabled」守卫(utls conn.go:1702),快路 exporter 取不出。
	// TLS 1.3 无 renegotiation + 握手已完成 → 复位为 RenegotiateNever 解锁 exporter;hello 字节已发,
	// SecureRenegotiationSupported 指纹保真度不受影响。UClient 不 clone config(u_conn.go:64,直接用传入
	// 指针)→ tlsCfg 即 uConn.config → 此复位在 ConnectionState().ExportKeyingMaterial 时生效。
	tlsCfg.Renegotiation = utls.RenegotiateNever
	return &tlsConn{c: c}, nil
}

// tlsConn 包 *utls.UConn:既是字节流(转发 Read/Write/Close)又取 exporter。
type tlsConn struct{ c *utls.UConn }

func (t *tlsConn) Read(p []byte) (int, error)  { return t.c.Read(p) }
func (t *tlsConn) Write(p []byte) (int, error) { return t.c.Write(p) }
func (t *tlsConn) Close() error                { return t.c.Close() }

// Exporter 取快路 exporter(stdlib tls.ConnectionState.ExportKeyingMaterial,RFC 5705)。
// 委派 [tlsConn.ExporterWithLabel](stream label);L4 起底层由 label 参变,Exporter() 仅便利别名。
// 注意:ExportKeyingMaterial 是指针 receiver(*ConnectionState),须先存本地变量取地址。
func (t *tlsConn) Exporter() ([crypto.KeyLen]byte, error) {
	return t.ExporterWithLabel(crypto.ExporterLabel)
}

// ExporterWithLabel 按指定 label 取 TLS exporter(L4 新增;datagram 路用 crypto.UDPExporterLabel,
// 与 stream crypto.ExporterLabel 域分离 → 独立密钥)。对照 Rust TcpTlsConn::export_keying_material。
func (t *tlsConn) ExporterWithLabel(label string) ([crypto.KeyLen]byte, error) {
	var out [crypto.KeyLen]byte
	state := t.c.ConnectionState()
	b, err := state.ExportKeyingMaterial(label, nil, crypto.KeyLen)
	if err != nil {
		return out, fmt.Errorf("transport: tls exporter: %w", err)
	}
	copy(out[:], b)
	return out, nil
}

// utlsClientConfig 构造 uTLS Config(TCP arm;镜像 Rust build_client_cfg 三分支)。
//
// **ALPN 用 Chrome 原生 [h2, http/1.1]**(不覆写 cfg.ALPN / 不设 NextProtos)—— 21 单栈服务端 peek TLS
// appdata 分流、不 gate ALPN,发浏览器原生 ALPN 反而保 JA4 保真度(cfg.ALPN 现仅 QUIC 路 quicTLSConfig 用)。
// **不设 MinVersion**:HelloChrome_Auto 的 supported_versions 已含 [1.3, 1.2](真 Chrome),speedcat 服务端
// rustls 恒 TLS 1.3 → 必落 1.3(exporter 成立);强设 MinVersion 反会削 Chrome supported_versions 保真度。
func utlsClientConfig(cfg Config) (*utls.Config, error) {
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Host // Rust config.rs SNI 缺省 = host
	}
	tc := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: cfg.Insecure, // --insecure 旁路(fail-safe:默认 false = 校验)
	}
	if cfg.CAFile != "" { // --ca pin(替换系统 roots)
		pool, err := loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

// loadCAPool 读 PEM 文件构造 x509 pool(pin 替换系统 roots)。TCP/QUIC 共用。
func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("transport: 读 CA %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("transport: CA %s 无有效证书", path)
	}
	return pool, nil
}
