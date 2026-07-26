// relay_test.go —— TCP relay pump self-test(net.Pipe 端到端回环 + pumpDecode 错误路径)。
//
// 镜像 Rust relay.rs 的双向桥接 + 半关级联语义。测法:net.Pipe 两端各跑一「侧」,client 侧 = Relay(txA/rxA),
// peer 侧 = mirrorEcho(用 txB/rxB 镜像,把 client 发来的 TcpData 原样加密回送)。证:加解密跨方向互通 +
// EOF 级联(TcpClose)→ Relay 返 nil 良性。
//
// 密钥方向分离(对照真实 C2S/S2C 双向独立 key):txA/rxB 共享 k1(C2S),txB/rxA 共享 k2(S2C)→ 无 nonce 复用。
// 密钥确定性填充(非生产),测试只 bytes.Equal / errors.Is,不打 raw。

package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// relayHalves 构造 client 侧 (txA,rxA) + peer 侧 (txB,rxB),方向化密钥(C2S=k1 / S2C=k2)。
func relayHalves(noInner bool) (txA, rxA, txB, rxB SessionLike) {
	k1, n1 := testKeyNonce(0x70) // C2S
	k2, n2 := testKeyNonce(0x80) // S2C
	return SessionLike{
			tx: SessionTx{key: k1, nonceBase: n1, noInnerAEAD: noInner},
			rx: SessionRx{key: k2, nonceBase: n2, noInnerAEAD: noInner},
		},
		SessionLike{
			tx: SessionTx{key: k2, nonceBase: n2, noInnerAEAD: noInner}, // peer S2C tx = client S2C rx 的 key
			rx: SessionRx{key: k1, nonceBase: n1, noInnerAEAD: noInner}, // peer C2S rx = client C2S tx 的 key
		}, SessionLike{}, SessionLike{}
}

// SessionLike 一侧的 tx+rx 对(测试便利;client 与 peer 各一份)。
type SessionLike struct {
	tx SessionTx
	rx SessionRx
}

// TestRelayEcho 两分支(快路/伪装路)各:localApp 写 → relay → mirrorEcho 回送 → localApp 读回原字节;
// 随后关 localApp → EOF 级联 → Relay 返 nil 良性(对照 Rust try_join! + TcpClose 半关级联)。
func TestRelayEcho(t *testing.T) {
	for _, noInner := range []bool{true, false} {
		t.Run(armName(noInner), func(t *testing.T) {
			a, b, _, _ := relayHalves(noInner)

			connClient, connPeer := net.Pipe()
			localClient, localApp := net.Pipe()

			peerDone := make(chan error, 1)
			go func() { peerDone <- mirrorEcho(connPeer, &b.tx, &b.rx) }()

			relayDone := make(chan error, 1)
			go func() { relayDone <- Relay(&a.tx, &a.rx, connClient, localClient) }()

			msg := []byte("speedcat-relay-echo-payload")
			if _, err := localApp.Write(msg); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(localApp, got); err != nil {
				t.Fatalf("读回环: %v", err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatal("echo 回环字节不一致")
			}

			// 关 app → pumpEncode 收 EOF 发 TcpClose → peer 回 TcpClose → pumpDecode 收 EOF → Relay 返 nil。
			localApp.Close()

			select {
			case err := <-relayDone:
				if err != nil {
					t.Fatalf("Relay 应返 nil(良性级联), got %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Relay 未返回(半关级联卡死?)")
			}
			select {
			case <-peerDone:
			case <-time.After(2 * time.Second):
				t.Fatal("peer 未返回")
			}
		})
	}
}

// armName 测试子名(快路/伪装路)。
func armName(noInner bool) string {
	if noInner {
		return "fast"
	}
	return "disguise"
}

// mirrorEcho peer 侧镜像:读 client 发来的帧,TcpData → 原样加密回送(echo),TcpClose → 回 TcpClose 退出。
func mirrorEcho(conn net.Conn, tx *SessionTx, rx *SessionRx) error {
	var out []byte
	for {
		hdr, body, err := ReadFrame(conn)
		if err != nil {
			return err
		}
		ft, payload, err := rx.DecryptFrame(hdr, body, &out)
		if err != nil {
			return err
		}
		switch ft {
		case wire.FrameTCPData:
			var echo []byte
			if _, e := tx.EncryptFrameInto(wire.FrameTCPData, payload, &echo); e != nil {
				return e
			}
			if _, e := conn.Write(echo); e != nil {
				return e
			}
		case wire.FrameTCPClose:
			var echo []byte
			if _, e := tx.EncryptFrameInto(wire.FrameTCPClose, nil, &echo); e != nil {
				return e
			}
			_, _ = conn.Write(echo)
			return nil
		default:
			return ErrUnexpectedFrame
		}
	}
}

// TestPumpDecodePeerError peer 发 Error 帧 → pumpDecode 返 ErrPeer(payload 透出,对照 Rust Error::Peer)。
func TestPumpDecodePeerError(t *testing.T) {
	a, b, _, _ := relayHalves(true)
	connClient, connPeer := net.Pipe()
	defer connClient.Close()
	defer connPeer.Close()

	var fr []byte
	if _, err := b.tx.EncryptFrameInto(wire.FrameError, []byte("dial failed"), &fr); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = connPeer.Write(fr) }()

	localClient, localApp := net.Pipe()
	defer localApp.Close()
	if err := pumpDecode(&a.rx, connClient, localClient); !errors.Is(err, ErrPeer) {
		t.Fatalf("应 ErrPeer, got %v", err)
	}
}

// TestPumpDecodeUnexpectedFrame 数据泵收到非数据帧(如 Ping)→ ErrUnexpectedFrame(fail-loud)。
func TestPumpDecodeUnexpectedFrame(t *testing.T) {
	a, b, _, _ := relayHalves(true)
	connClient, connPeer := net.Pipe()
	defer connClient.Close()
	defer connPeer.Close()

	var fr []byte
	if _, err := b.tx.EncryptFrameInto(wire.FramePing, []byte("x"), &fr); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = connPeer.Write(fr) }()

	localClient, localApp := net.Pipe()
	defer localApp.Close()
	if err := pumpDecode(&a.rx, connClient, localClient); !errors.Is(err, ErrUnexpectedFrame) {
		t.Fatalf("应 ErrUnexpectedFrame, got %v", err)
	}
}
