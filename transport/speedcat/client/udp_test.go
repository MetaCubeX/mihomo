// udp_test.go —— runStreamTunnel 流隧道臂回环 self-test(锁三退出路径 + 双向 UdpPacket 互通)。
//
// 用 net.Pipe 串两端 runStreamTunnel(client 端 + server 端),手卷对称 Session 半(C2S=k1/S2C=k2):
//   - 双向:client.cmd → 帧 → server.reply / server.cmd → 帧 → client.reply(两向 UdpData 帧 + Session AEAD)。
//   - 退出路径①(local close):A 关 done → A writer 退 → 关 conn → B reader EOF 退 → B writer stop 退。
//   - 退出路径②(remote close):关 doneB → b 关 → A reader ReadFrame EOF 退(非 done 触发,真实服务端掉线)。
//
// datagram 臂(QUIC 原生 datagram)需真 QUIC conn,留 C4 跨实现 e2e(本测试只锁流隧道臂纯逻辑)。

package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
)

// errNoExporter 测试用:pipeConn 无真实 exporter(流隧道臂不取,故永不触发)。
var errNoExporter = errors.New("udp_test: pipeConn 无 exporter")

// pipeConn 包 net.Pipe 端,凑齐 transport.Conn(流隧道臂只用 Read/Write/Close;Exporter 永不调)。
type pipeConn struct{ net.Conn }

func (pipeConn) Exporter() ([crypto.KeyLen]byte, error) { return [crypto.KeyLen]byte{}, errNoExporter }
func (pipeConn) ExporterWithLabel(string) ([crypto.KeyLen]byte, error) {
	return [crypto.KeyLen]byte{}, errNoExporter
}

// udpTunnelHalves 构造 client/server 对称 Session 半(C2S=k1 seed0x70 / S2C=k2 seed0x80)。
// 返回 (clientTx, clientRx, serverTx, serverRx);client tx=C2S/rx=S2C,server tx=S2C/rx=C2S(镜像配对)。
func udpTunnelHalves(noInner bool) (SessionTx, SessionRx, SessionTx, SessionRx) {
	k1, n1 := testKeyNonce(0x70) // C2S(client→server)
	k2, n2 := testKeyNonce(0x80) // S2C(server→client)
	clientTx := SessionTx{key: k1, nonceBase: n1, noInnerAEAD: noInner}
	clientRx := SessionRx{key: k2, nonceBase: n2, noInnerAEAD: noInner}
	serverTx := SessionTx{key: k2, nonceBase: n2, noInnerAEAD: noInner}
	serverRx := SessionRx{key: k1, nonceBase: n1, noInnerAEAD: noInner}
	return clientTx, clientRx, serverTx, serverRx
}

// waitReplyClosed 轮询 reply 是否在 timeout 内关闭(ok=false);验证退出路径关 reply(无泄漏)。
func waitReplyClosed(t *testing.T, name string, ch <-chan UdpPacket, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case _, ok := <-ch:
			if !ok {
				return // 已关
			}
		default:
		}
		time.Sleep(3 * time.Millisecond)
	}
	t.Fatalf("%s 在 %v 内未关(退出路径泄漏)", name, timeout)
}

// TestStreamTunnelLoopback 双向 UdpPacket 互通 + Close 退出路径(快路 + 伪装路两 noInner 分支)。
func TestStreamTunnelLoopback(t *testing.T) {
	for _, noInner := range []bool{true, false} {
		arm := "disguise"
		if noInner {
			arm = "fast"
		}
		t.Run(arm, func(t *testing.T) {
			cTx, cRx, sTx, sRx := udpTunnelHalves(noInner)
			a, b := net.Pipe() // a=client 端 / b=server 端,双向字节流
			pa, pb := &pipeConn{a}, &pipeConn{b}

			cmdA, replyA, doneA := make(chan UdpPacket, 4), make(chan UdpPacket, 4), make(chan struct{})
			cmdB, replyB, doneB := make(chan UdpPacket, 4), make(chan UdpPacket, 4), make(chan struct{})

			go runStreamTunnel(pa, &cTx, &cRx, cmdA, replyA, doneA)
			go runStreamTunnel(pb, &sTx, &sRx, cmdB, replyB, doneB)

			// client → server:写 client 的 cmd,读 server 的 reply。
			pkt := UdpPacket{Addr: dgAddr(), Data: []byte("client->server")}
			cmdA <- pkt
			select {
			case got := <-replyB:
				if got.Addr != pkt.Addr || string(got.Data) != string(pkt.Data) {
					t.Fatalf("client→server 不一致: %+v", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("client→server 超时")
			}

			// server → client:写 server 的 cmd,读 client 的 reply。
			pkt2 := UdpPacket{Addr: dgAddr(), Data: []byte("server->client")}
			cmdB <- pkt2
			select {
			case got := <-replyA:
				if got.Addr != pkt2.Addr || string(got.Data) != string(pkt2.Data) {
					t.Fatalf("server→client 不一致: %+v", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("server→client 超时")
			}

			// 退出路径:关 doneA → A writer 退 → 关 a → B reader EOF 退 → 两 reply 关(无泄漏)。
			close(doneA)
			waitReplyClosed(t, "replyA", replyA, 2*time.Second)
			waitReplyClosed(t, "replyB", replyB, 2*time.Second)
			close(doneB) // 清理(B 已退;未关的 doneB 关之)
		})
	}
}

// TestStreamTunnelRemoteCloseExit server 端先退(关 doneB)→ 关 b → client reader ReadFrame EOF 退 → replyA 关。
// 锁「remote-close 经 ReadFrame 错退」路径(非 done 触发,真实服务端掉线场景)+ RecvFrom 见 ErrTunnelClosed。
func TestStreamTunnelRemoteCloseExit(t *testing.T) {
	cTx, cRx, sTx, sRx := udpTunnelHalves(true) // 快路
	a, b := net.Pipe()
	pa, pb := &pipeConn{a}, &pipeConn{b}

	cmdA, replyA, doneA := make(chan UdpPacket, 4), make(chan UdpPacket, 4), make(chan struct{})
	cmdB, replyB, doneB := make(chan UdpPacket, 4), make(chan UdpPacket, 4), make(chan struct{})

	go runStreamTunnel(pa, &cTx, &cRx, cmdA, replyA, doneA)
	go runStreamTunnel(pb, &sTx, &sRx, cmdB, replyB, doneB)

	// server 端先退 → b 关 → client(A)reader EOF 退 → 两 reply 关。
	close(doneB)
	waitReplyClosed(t, "replyB", replyB, 2*time.Second)
	waitReplyClosed(t, "replyA", replyA, 2*time.Second)

	// client 的 RecvFrom 语义:replyA 已关 → ErrTunnelClosed。
	tun := &UdpTunnel{cmd: cmdA, reply: replyA, done: doneA, closeOnce: sync.Once{}}
	rctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := tun.RecvFrom(rctx); !errors.Is(err, ErrTunnelClosed) {
		t.Fatalf("reply 关后 RecvFrom 须 ErrTunnelClosed, got %v", err)
	}
	close(doneA)
}
