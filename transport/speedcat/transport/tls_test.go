// tls_test.go —— TCP+TLS arm self-test:Go 两端握手 → 两端 exporter 字节相等 + IO round-trip。
// 不依赖 Rust(跨实现铁证留 e2e:Go client ↔ Rust server,L3 auth_tag 验字节)。
// exporter 是密钥 → 只 bytes.Equal,绝不打印(§5.4)。

package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
)

// TestTCP_TLSExporterAndIO 验证 TCP+TLS arm:
//  1. Go client 经 transport.Dial(KindTCP) 握手过;
//  2. 两端 ExportKeyingMaterial(同 label,RFC 5705)字节相等(铁证 exporter 取对了);
//  3. Conn IO round-trip(ping → echo)。
func TestTCP_TLSExporterAndIO(t *testing.T) {
	der, key := testCert(t)
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer ln.Close()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// server:裸 *tls.Conn(transport 是 client-only,server 不经它)。握手后取 exporter + echo。
	srvErr := make(chan error, 1)
	go func() {
		defer close(srvErr)
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			srvErr <- err
			return
		}
		// 取 server 端 exporter,写给 client(32B),client 与自身 exporter 比对。
		state := tc.ConnectionState()
		srvExp, err := state.ExportKeyingMaterial(crypto.ExporterLabel, nil, crypto.KeyLen)
		if err != nil {
			srvErr <- err
			return
		}
		if _, err := tc.Write(srvExp); err != nil {
			srvErr <- err
			return
		}
		// echo loop:读 4B 写回 4B。
		buf := make([]byte, 4)
		if _, err := io.ReadFull(tc, buf); err != nil {
			srvErr <- err
			return
		}
		if _, err := tc.Write(buf); err != nil {
			srvErr <- err
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// client:Insecure=true(self-test 不验证书链;CA pin 路径留 e2e)。
	conn, err := Dial(ctx, Config{Host: host, Port: port, Insecure: true}, KindTCP)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	cliExp, err := conn.Exporter()
	if err != nil {
		t.Fatalf("client exporter: %v", err)
	}
	if len(cliExp) != crypto.KeyLen {
		t.Fatalf("exporter len = %d, want %d", len(cliExp), crypto.KeyLen)
	}
	// 读 server exporter(32B)→ 与 client exporter 比对(应逐字节等:同 label 同 master secret)。
	srvExp := make([]byte, crypto.KeyLen)
	if _, err := io.ReadFull(conn, srvExp); err != nil {
		t.Fatalf("read server exporter: %v", err)
	}
	if !bytes.Equal(cliExp[:], srvExp) {
		t.Fatalf("exporter 两端不等(应 RFC 5705 同 label 同密钥流逐字节等)")
	}
	// IO round-trip:ping → echo。
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	pong := make([]byte, 4)
	if _, err := io.ReadFull(conn, pong); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if !bytes.Equal(pong, []byte("ping")) {
		t.Fatalf("echo mismatch: %q", pong)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}
