// datagram_cipher.go —— UDP datagram 独立 AEAD 上下文(镜像 Rust datagram.rs:39-89)。
//
// **为何不复用 Session:** Session 的 nonce = base XOR 单调 ctr + 严格递增重放检查(ctr <= highest → ErrReplay)。
// UDP datagram **无序 / 可丢 / 可重传**,强行走 Session → 任何乱序帧触发重放,且需共享可变 ctr(热路径锁)→ 不可用。
// 故 UDP 走**独立** AEAD 上下文 DatagramCipher。
//
// # 设计
//   - 密钥:TLS exporter,label = [crypto.UDPExporterLabel](`speedcat-udp-v1`),与 stream 的
//     `speedcat-v1 exporter` **域分离** → 独立 32B 密钥。两端 post-handshake 各自派生、字节一致(RFC 5705 对称)。
//   - Nonce:每 datagram 随机 12B(crypto/rand CSPRNG)。**无 ctr、无重放窗口、无共享可变状态** → 多 ASSOC 并发 send
//     零协调(热路径无锁)。碰撞:birthday bound ~2⁴⁸ datagrams,远超连接生命周期。
//   - 不加重放保护:UDP 网络层本就可被重放;应用层重放(DNS txn id / QUIC initial)归应用,隧道不加第二层。
//
// # 线格式(单 datagram payload)
//
//	[nonce:12][AEAD_ct(header + frag_payload)]
//
// nonce 明文前置(接收方需 nonce 才能解密); header 与 frag_payload 均在密文内(ASSOC_ID 也加密)。
// AAD = 空。
//
// **热路径:** Seal/Open 各 1 次 alloc(同 Session AEAD 成本);MVP 先正确,零拷贝留收尾。**禁每 datagram 日志**。
// **panic-free**(被 mihomo import 的库:AEAD/随机错返 error)。
//
// 导出密钥/key 是密钥 —— self-test 只 bytes.Equal / errors.Is,**绝不打 raw**(对照 Rust datagram.rs 测试)。

package client

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/mihomo/transport/speedcat/transport"
)

// ErrDatagramExporter exporter 不可用(传输无 TLS exporter;fail-loud,不静默退到无加密)。
var ErrDatagramExporter = errors.New("client/datagram: TLS exporter 不可用(传输无 exporter)")

// ErrDatagramTruncated 帧过短(< nonce + tag,被截断或非本协议)。
var ErrDatagramTruncated = errors.New("client/datagram: 帧过短(< nonce + tag)")

// DatagramCipher UDP datagram 独立 AEAD 上下文(随机 nonce、无 ctr、无重放窗口)。
// 由 [NewDatagramCipher] 从 TLS exporter 派生(两端对称);持有 32B key。可被多 ASSOC 共享(immutable)。
type DatagramCipher struct {
	key crypto.Key
}

// NewDatagramCipher 从 conn 的 TLS exporter 派生(label=crypto.UDPExporterLabel,与 stream 域分离)。
// exporter 不可用 → fail-loud(凭据安全铁律:不静默退到无加密)。
func NewDatagramCipher(conn transport.Conn) (*DatagramCipher, error) {
	key, err := conn.ExporterWithLabel(crypto.UDPExporterLabel)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatagramExporter, err)
	}
	return &DatagramCipher{key: key}, nil
}

// NewDatagramCipherFromKey 从已知 key 构造(测试 / 已派生 key 直用;对照 Rust DatagramCipher::from_key)。
func NewDatagramCipherFromKey(key crypto.Key) *DatagramCipher { return &DatagramCipher{key: key} }

// Seal 加密:输出 = [nonce:12][ct+tag]。AAD = 空。nonce 每 datagram 随机(crypto/rand)。
func (c *DatagramCipher) Seal(plain []byte) ([]byte, error) {
	var nonce [crypto.NonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("client/datagram: rand nonce: %w", err)
	}
	ct, err := crypto.AEADEncrypt(c.key, nonce, plain, nil)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, crypto.NonceLen+len(ct))
	out = append(out, nonce[:]...)
	out = append(out, ct...)
	return out, nil
}

// Open 解密:输入 [nonce:12][ct+tag] → 明文。过短 / tag 不符 → Err(对照 Rust DatagramCipher::open)。
func (c *DatagramCipher) Open(wire []byte) ([]byte, error) {
	if len(wire) < crypto.NonceLen+crypto.TagLen {
		return nil, ErrDatagramTruncated
	}
	var nonce [crypto.NonceLen]byte
	copy(nonce[:], wire[:crypto.NonceLen])
	return crypto.AEADDecrypt(c.key, nonce, wire[crypto.NonceLen:], nil)
}
