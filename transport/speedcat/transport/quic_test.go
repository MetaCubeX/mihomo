// quic_test.go —— QUIC arm self-test:Go 两端握手 → 两端 exporter 字节相等 + stream round-trip。
// 不依赖 Rust(跨实现铁证留 e2e:Go client ↔ Rust server,决策 5 ALPN 命门实测)。
// exporter 是密钥 → 只 bytes.Equal,绝不打印(§5.4)。

package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/quic-go"
	mtls "github.com/metacubex/tls"
)

// TestQUIC_ExporterAndIO 验证 QUIC arm:
//  1. Go client 经 transport.Dial(KindQUIC) 握手过 + open stream;
//  2. 两端 exporter 字节相等(铁证 exporter 取自父 conn 取对了);
//  3. stream IO round-trip(ping → echo)。
//
// ALPN 命门:Go quic-go 两端固定 NextProtos=SpeedcatALPN(self-test 不碰 Rust;
// 对 Rust server 的空-ALPN 实测是决策 5 的 e2e 落点,另测)。
func TestQUIC_ExporterAndIO(t *testing.T) {
	der, key := testCert(t)
	serverCfg := &mtls.Config{
		Certificates: []mtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{SpeedcatALPN}, // Go quic-go 两端需非空 ALPN,固定 speedcat/1
		MinVersion:   mtls.VersionTLS13,
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", serverCfg, &quic.Config{})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer ln.Close()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// server:accept conn → accept client-opened stream → 读 client exporter + 回 server exporter + echo。
	// QUIC bidi stream 须 client 先写(发 STREAM 帧)才在 server 端物化 —— 故 client 先写 exporter。
	srvErr := make(chan error, 1)
	go func() {
		defer close(srvErr)
		conn, err := ln.Accept(context.Background())
		if err != nil {
			srvErr <- err
			return
		}
		// 不在此关父 conn(关了 → 0x0 app error 与 client 读 pong 竞态);只关 stream(发 FIN)。
		// 父 conn 由测试外层 defer ln.Close() 兜底拆除。
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			srvErr <- err
			return
		}
		defer stream.Close()
		// client 先写 32B exporter → stream 物化 + 数据到。
		cliExp := make([]byte, crypto.KeyLen)
		if _, err := io.ReadFull(stream, cliExp); err != nil {
			srvErr <- err
			return
		}
		// exporter 取自**父 conn**(非 stream),写回 client 比对。
		tlsState := conn.ConnectionState().TLS
		srvExp, err := tlsState.ExportKeyingMaterial(crypto.ExporterLabel, nil, crypto.KeyLen)
		if err != nil {
			srvErr <- err
			return
		}
		if _, err := stream.Write(srvExp); err != nil {
			srvErr <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(stream, buf); err != nil {
			srvErr <- err
			return
		}
		if _, err := stream.Write(buf); err != nil {
			srvErr <- err
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, Config{Host: host, Port: port, Insecure: true, ALPN: SpeedcatALPN}, KindQUIC)
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
	// client 先写 exporter → QUIC stream 物化(否则 server AcceptStream 永不返,死锁)。
	if _, err := conn.Write(cliExp[:]); err != nil {
		t.Fatalf("write client exporter: %v", err)
	}
	srvExp := make([]byte, crypto.KeyLen)
	if _, err := io.ReadFull(conn, srvExp); err != nil {
		t.Fatalf("read server exporter: %v", err)
	}
	if !bytes.Equal(cliExp[:], srvExp) {
		t.Fatalf("exporter 两端不等(应 RFC 5705 同 label 同密钥流逐字节等)")
	}
	// stream IO round-trip:ping → echo。
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
