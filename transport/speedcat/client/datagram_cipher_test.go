// datagram_cipher_test.go —— DatagramCipher self-test(seal/open round-trip + 随机 nonce + 篡改 + 错 key + 过短拒)。
// 镜像 Rust datagram.rs:99-148 测试,逐项对应。只 bytes.Equal / errors.Is,不打 raw。

package client

import (
	"bytes"
	"errors"
	"testing"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
)

// dgKeyA/dgKeyB 确定性 32B key(self-test;**非生产**)。
func dgKeyA() crypto.Key {
	var k crypto.Key
	for i := range k {
		k[i] = 1
	}
	return k
}

func dgKeyB() crypto.Key {
	var k crypto.Key
	for i := range k {
		k[i] = 2
	}
	return k
}

// TestDatagramSealOpenRoundtrip 多长度明文(空 / 短 / 长)round-trip 须还原;wire 必以 nonce+tag 长度起步。
func TestDatagramSealOpenRoundtrip(t *testing.T) {
	c := NewDatagramCipherFromKey(dgKeyA())
	for _, msg := range [][]byte{{}, []byte("hi"), bytes.Repeat([]byte("x"), 100)} {
		wire, err := c.Seal(msg)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		pt, err := c.Open(wire)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatal("roundtrip 须还原明文")
		}
		if len(wire) < crypto.NonceLen+crypto.TagLen {
			t.Fatal("wire 须 ≥ nonce+tag")
		}
	}
}

// TestDatagramRandomNonce 随机 nonce → 同明文两次 seal 的密文(含 nonce)不同(防 nonce 重用观测)。
func TestDatagramRandomNonce(t *testing.T) {
	c := NewDatagramCipherFromKey(dgKeyA())
	w1, err := c.Seal([]byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	w2, err := c.Seal([]byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(w1, w2) {
		t.Fatal("随机 nonce 须使两次密文不同")
	}
	if pt, err := c.Open(w1); err != nil || !bytes.Equal(pt, []byte("same")) {
		t.Fatalf("w1 open: %v %s", err, pt)
	}
	if pt, err := c.Open(w2); err != nil || !bytes.Equal(pt, []byte("same")) {
		t.Fatalf("w2 open: %v %s", err, pt)
	}
}

// TestDatagramTamper 翻转密文一字节 → tag 校验失败 → Err。
func TestDatagramTamper(t *testing.T) {
	c := NewDatagramCipherFromKey(dgKeyA())
	wire, err := c.Seal([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	wire[crypto.NonceLen+3] ^= 0xff
	if _, err := c.Open(wire); err == nil {
		t.Fatal("篡改密文须解密失败")
	}
}

// TestDatagramWrongKey 异 key 须解密失败(exporter 域分离 / 错配场景)。
func TestDatagramWrongKey(t *testing.T) {
	seal := NewDatagramCipherFromKey(dgKeyA())
	open := NewDatagramCipherFromKey(dgKeyB())
	wire, err := seal.Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open.Open(wire); err == nil {
		t.Fatal("异 key 须解密失败")
	}
}

// TestDatagramOpenTooShort 过短(< nonce+tag / 空)→ ErrDatagramTruncated。
func TestDatagramOpenTooShort(t *testing.T) {
	c := NewDatagramCipherFromKey(dgKeyA())
	if _, err := c.Open(make([]byte, 5)); !errors.Is(err, ErrDatagramTruncated) {
		t.Fatalf("应 ErrDatagramTruncated, got %v", err)
	}
	if _, err := c.Open(nil); !errors.Is(err, ErrDatagramTruncated) {
		t.Fatalf("应 ErrDatagramTruncated, got %v", err)
	}
}
