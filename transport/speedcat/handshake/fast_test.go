// fast_test.go —— 快路 Go↔Go self-test(net.Pipe 两端跑 fast 握手:正确 PSK 两端密钥相等 +
// 错 PSK AuthTagMismatch;证 fast_client + auth_tag 链 Go 内自洽)。
//
// 快路用喂入的确定 exporter(隔离 handshake 帧+auth_tag+派生;真实 exporter 抽取在 transport/ 测,
// 真实路径由跨实现 e2e 验)。§5.4:auth_tag/密钥绝不打 raw —— 失败消息不带字节。

package handshake

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// TestFast_CorrectPSK_KeysEqual:同 exporter + 同 PSK → server ct_eq 验过 → 两端密钥相等(同 exporter IKM)
// + 两端 NoInnerAEAD 置位 + client/server caps 一致(params 同 → 协商 = 自身 + bit8)。
func TestFast_CorrectPSK_KeysEqual(t *testing.T) {
	exporter := testExporter()
	psk := testPsk()
	params := Params{Caps: wire.CapHasDatagram | wire.CapUDPTunnelOK, MaxBandwidth: 2_000_000}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var serverSess *Session
	serverErr := make(chan error, 1)
	go func() {
		var err error
		serverSess, err = FastServer(serverConn, psk, params, exporter)
		serverErr <- err
	}()

	clientSess, err := fastClient(clientConn, psk, params, exporter)
	if err != nil {
		t.Fatalf("client fast: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server fast: %v", err)
	}

	// 两端从同 exporter 派生 → 密钥字节相等。
	if !keysEqual(clientSess.Keys, serverSess.Keys) {
		t.Fatal("两端 Session.Keys 不等(快路 exporter 派生分叉)")
	}
	// 快路 force 置 NO_INNER_AEAD(架构不变量,ADR-007)。
	if !clientSess.Caps.NoInnerAEAD() || !serverSess.Caps.NoInnerAEAD() {
		t.Fatal("快路 NoInnerAEAD 应置位")
	}
	// caps:client = params + bit8(乐观,无协商);server = negotiate(params,params) + bit8 = params + bit8。
	if clientSess.Caps != serverSess.Caps {
		t.Fatal("两端 Caps 不一致")
	}
	// max_bw:client = 声明;server = clamp(声明,策略上限=声明) = 声明。
	if clientSess.MaxBandwidth != params.MaxBandwidth || serverSess.MaxBandwidth != params.MaxBandwidth {
		t.Fatalf("max_bw client=%d server=%d want %d", clientSess.MaxBandwidth, serverSess.MaxBandwidth, params.MaxBandwidth)
	}
}

// TestFast_WrongPSK_AuthTagMismatch:错 PSK → server FastAuthTag 重算 ≠ 客户端 tag → ct_eq 失败 →
// ErrAuthTagMismatch(决定性鉴权铁证,对照 Rust fast_server crypto::ct_eq)。
func TestFast_WrongPSK_AuthTagMismatch(t *testing.T) {
	exporter := testExporter()
	params := Params{Caps: wire.CapHasDatagram, MaxBandwidth: 0}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverErr := make(chan error, 1)
	go func() {
		// server 用不同 PSK(正确 exporter)。
		_, err := FastServer(serverConn, testPsk2(), params, exporter)
		serverErr <- err
	}()

	// client 用 testPsk 写 FastHello(只写,不读 —— 故 client 端不发错)。
	if _, err := fastClient(clientConn, testPsk(), params, exporter); err != nil {
		t.Fatalf("client fast 写 FastHello: %v", err)
	}
	if err := <-serverErr; err != ErrAuthTagMismatch {
		t.Fatalf("错 PSK 应 ErrAuthTagMismatch,got err=%v", err)
	}
}
