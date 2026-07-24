// disguise_test.go —— 伪装路 Go↔Go self-test(net.Pipe 两端跑 disguise 握手,证 DH+MAC+derive+hs-input 链 Go 内自洽)。
//
// §5.4:导出密钥/exporter/auth_tag 是密钥 —— 测试只 bytes.Equal,**绝不打 raw**;失败消息也不带字节。
// 共享 helper(testPsk/testPsk2/testExporter)本文件定义,fast_test.go 同包复用。

package handshake

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// testPsk 确定性 32B PSK(self-test 用;**非生产密钥**,永不复用到生产 —— §6.3)。
func testPsk() crypto.Psk {
	var p crypto.Psk
	for i := range p {
		p[i] = byte(i) + 1 // 01 02 03 … 20
	}
	return p
}

// testPsk2 与 testPsk 字节不同的确定性 PSK(测 fast 鉴权失败 / disguise key 分叉)。
func testPsk2() crypto.Psk {
	var p crypto.Psk
	for i := range p {
		p[i] = 0x55
	}
	return p
}

// testExporter 确定性 32B exporter(快路 self-test 喂入;真实 exporter 抽取在 transport/ 测,
// 这里隔离 handshake 帧编解码 + auth_tag + 派生逻辑 —— 真实 exporter 路径由跨实现 e2e 验)。
func testExporter() [crypto.KeyLen]byte {
	var e [crypto.KeyLen]byte
	for i := range e {
		e[i] = byte(0xA0 + i) // A0 A1 … BF
	}
	return e
}

// keysEqual 比两套会话子密钥全相等(C2SKey/S2CKey/C2SNonce/S2CNonce)。定长数组可直接 ==。
func keysEqual(a, b crypto.SessionKeys) bool {
	return a.C2SKey == b.C2SKey && a.S2CKey == b.S2CKey &&
		a.C2SNonce == b.C2SNonce && a.S2CNonce == b.S2CNonce
}

// TestDisguise_BothEndsKeysEqual:net.Pipe 两端同 PSK 跑 disguise 握手 → 两端 Session.Keys 字节相等
// + 两端 NoInnerAEAD 清位 + max_bw 各取自身声明(证 DH+MAC+derive+hs_input 链 Go 内自洽)。
func TestDisguise_BothEndsKeysEqual(t *testing.T) {
	psk := testPsk()
	params := Params{Caps: wire.CapHasDatagram | wire.CapUDPTunnelOK, MaxBandwidth: 1_000_000}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var serverSess *Session
	serverErr := make(chan error, 1)
	go func() {
		var err error
		serverSess, err = DisguiseServer(serverConn, psk, params)
		serverErr <- err
	}()

	clientSess, err := disguiseClient(clientConn, psk, params)
	if err != nil {
		t.Fatalf("client disguise: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server disguise: %v", err)
	}

	// 两端密钥字节相等(链路自洽铁证)。
	if !keysEqual(clientSess.Keys, serverSess.Keys) {
		t.Fatal("两端 Session.Keys 不等(伪装路密钥派生分叉)")
	}
	// 伪装路 force 清 NO_INNER_AEAD(架构不变量,ADR-007)。
	if clientSess.Caps.NoInnerAEAD() || serverSess.Caps.NoInnerAEAD() {
		t.Fatal("伪装路 NoInnerAEAD 应清位")
	}
	// max_bw:两端各记自身声明(params 同 → 相等)。
	if clientSess.MaxBandwidth != params.MaxBandwidth {
		t.Fatalf("client max_bw=%d want %d", clientSess.MaxBandwidth, params.MaxBandwidth)
	}
}

// TestDisguise_DifferentPSK_CompletesButKeysDiffer:伪装路**恒完成**(无显式 auth)—— 即便两端 PSK 不同,
// 握手也不报错;但 handshake_secret 分叉 → 两端密钥不同。证伪装路「握手成功 ≠ PSK 对」(包 doc 设计点)。
func TestDisguise_DifferentPSK_CompletesButKeysDiffer(t *testing.T) {
	params := Params{Caps: wire.CapHasDatagram, MaxBandwidth: 0}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var serverSess *Session
	serverErr := make(chan error, 1)
	go func() {
		var err error
		// server 用不同 PSK。
		serverSess, err = DisguiseServer(serverConn, testPsk2(), params)
		serverErr <- err
	}()

	// client 用 testPsk。握手应成功完成(无 auth)。
	clientSess, err := disguiseClient(clientConn, testPsk(), params)
	if err != nil {
		t.Fatalf("伪装路不同 PSK 仍应完成握手,got err=%v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server 伪装路不同 PSK 仍应完成,got err=%v", err)
	}
	// 但密钥不同(PSK 进 handshake_secret)。
	if keysEqual(clientSess.Keys, serverSess.Keys) {
		t.Fatal("不同 PSK 两端密钥竟相等(异常 —— handshake_secret 应分叉)")
	}
}
