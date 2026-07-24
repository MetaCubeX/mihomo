// tls.go —— TCP+TLS 1.3 dial arm(stdlib crypto/tls)。对照 Rust proto-tls/src/transport.rs:203 dial_tls。

package transport

import (
	"context"
	ctls "crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
)

// dialTCP 建立 TCP + TLS 1.3 连接,握手完成后返回 conn(exporter 此时可取)。
// 对照 Rust dial_tls:TcpStream::connect → TlsConnector::connect → TcpTlsConn。
func dialTCP(ctx context.Context, cfg Config) (Conn, error) {
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: tcp dial %s: %w", addr, err)
	}
	tlsCfg, err := stdTLSConfig(cfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	c := ctls.Client(raw, tlsCfg)
	// HandshakeContext:握手完成 exporter 可取(Rust dial_tls 握手后即用同款语义)。ctx 支持取消/超时。
	if err := c.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("transport: tls handshake %s: %w", addr, err)
	}
	return &tlsConn{c: c}, nil
}

// tlsConn 包 *crypto/tls.Conn:既是字节流(转发 Read/Write/Close)又取 exporter。
type tlsConn struct{ c *ctls.Conn }

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
// 与 stream crypto.ExporterLabel 域分离 → 独立密钥,ADR-009)。对照 Rust TcpTlsConn::export_keying_material。
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

// stdTLSConfig 按 Rust 三分支(cmd/mod.rs:46 build_client_cfg)构造 stdlib crypto/tls.Config(TCP arm)。
func stdTLSConfig(cfg Config) (*ctls.Config, error) {
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Host // Rust config.rs:720:SNI 缺省 = host
	}
	tc := &ctls.Config{
		ServerName:         sni,
		MinVersion:         ctls.VersionTLS13, // speedcat 强制 TLS 1.3(exporter + EMS 成立,ADR-007)
		InsecureSkipVerify: cfg.Insecure,      // --insecure 旁路(fail-safe:默认 false = 校验)
	}
	if cfg.ALPN != "" {
		tc.NextProtos = []string{cfg.ALPN}
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
