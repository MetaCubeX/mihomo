// session_test.go —— SessionTx/SessionRx self-test(快路/伪装路 round-trip + 重放拒 + ctr 耗尽 + 超长 + 篡改)。
//
// 密钥/auth_tag 是密钥 —— 测试只 bytes.Equal / errors.Is,**绝不打 raw**。密钥确定性填充(非生产)。
// 对照 Rust session.rs 的同款不变量(stream 保序 → ctr 严格递增;重放检查在 AEAD 后)。

package client

import (
	"bytes"
	"errors"
	"testing"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// testKeyNonce 确定性 32B key + 12B nonce base(self-test 用;**非生产密钥**,永不复用到生产)。
func testKeyNonce(seed byte) (crypto.Key, [crypto.NonceLen]byte) {
	var k crypto.Key
	for i := range k {
		k[i] = seed + byte(i)
	}
	var n [crypto.NonceLen]byte
	for i := range n {
		n[i] = seed*2 + byte(i)
	}
	return k, n
}

// TestSessionRoundTrip 快路(noInner=true)与伪装路(noInner=false)各做一次加解密 round-trip,
// 证两分支字节布局 + AEAD 自洽(对照 Rust encrypt/decrypt_frame_view)。
func TestSessionRoundTrip(t *testing.T) {
	for _, noInner := range []bool{true, false} {
		k, n := testKeyNonce(0x11)
		tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: noInner}
		rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: noInner}
		payload := []byte("speedcat-round-trip-payload")

		var enc []byte
		if _, err := tx.EncryptFrameInto(wire.FrameTCPData, payload, &enc); err != nil {
			t.Fatalf("noInner=%v: encrypt: %v", noInner, err)
		}
		hdr, err := wire.ParseHeader(enc[:wire.FrameHeaderLen])
		if err != nil {
			t.Fatalf("noInner=%v: parse hdr: %v", noInner, err)
		}
		var out []byte
		ft, got, err := rx.DecryptFrame(hdr, enc[wire.FrameHeaderLen:], &out)
		if err != nil {
			t.Fatalf("noInner=%v: decrypt: %v", noInner, err)
		}
		if ft != wire.FrameTCPData {
			t.Fatalf("noInner=%v: ftype 0x%02x != TCPData", noInner, byte(ft))
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("noInner=%v: payload 回环不一致", noInner)
		}
	}
}

// TestSessionCtrSequence 证 tx ctr 单调递增(首帧 0,次帧 1);rx 严格递增收(AEAD 后重放窗)。
func TestSessionCtrSequence(t *testing.T) {
	k, n := testKeyNonce(0x22)
	tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: true}
	rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: true}

	for i, wantCtr := range []uint32{0, 1, 2} {
		var enc []byte
		if _, err := tx.EncryptFrameInto(wire.FrameTCPData, []byte{byte(i)}, &enc); err != nil {
			t.Fatalf("frame %d: encrypt: %v", i, err)
		}
		hdr, _ := wire.ParseHeader(enc[:wire.FrameHeaderLen])
		if hdr.Ctr != wantCtr {
			t.Fatalf("frame %d: ctr %d != %d", i, hdr.Ctr, wantCtr)
		}
		var out []byte
		if _, _, err := rx.DecryptFrame(hdr, enc[wire.FrameHeaderLen:], &out); err != nil {
			t.Fatalf("frame %d: decrypt: %v", i, err)
		}
	}
}

// TestSessionReplay 证重放被拒:解出首帧(highest=ctr)后,同 ctr 再解 → ErrReplay(AEAD 成功后检查)。
func TestSessionReplay(t *testing.T) {
	k, n := testKeyNonce(0x33)
	tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: false}
	rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: false}

	var enc []byte
	if _, err := tx.EncryptFrameInto(wire.FrameTCPData, []byte("once"), &enc); err != nil {
		t.Fatal(err)
	}
	hdr, _ := wire.ParseHeader(enc[:wire.FrameHeaderLen])
	body := enc[wire.FrameHeaderLen:]

	var out []byte
	if _, _, err := rx.DecryptFrame(hdr, body, &out); err != nil {
		t.Fatalf("首帧应通过, got %v", err)
	}
	// 重放同帧(ctr <= highest)→ ErrReplay(易踩坑 #4)。
	if _, _, err := rx.DecryptFrame(hdr, body, &out); !errors.Is(err, ErrReplay) {
		t.Fatalf("重放应 ErrReplay, got %v", err)
	}
}

func TestSkippableUnknownDiscardedCriticalRejected(t *testing.T) {
	// 方案 1C:high-bit 未知(0x80+)→ 解码当 Padding 盲丢;低位未知(0x0B-0x7F)→ ParseHeader 拒。双路径(AEAD + 快路)。
	for _, noInner := range []bool{false, true} {
		k, n := testKeyNonce(0x44)
		tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: noInner}
		rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: noInner}
		// skippable 0x85(Go FrameType 是 byte,cast 造未知类型)。
		var enc []byte
		if _, err := tx.EncryptFrameInto(wire.FrameType(0x85), []byte("future-frame"), &enc); err != nil {
			t.Fatal(err)
		}
		hdr, err := wire.ParseHeader(enc[:wire.FrameHeaderLen])
		if err != nil {
			t.Fatalf("noInner=%v: skippable ParseHeader 应接受, got %v", noInner, err)
		}
		var out []byte
		ft, p, err := rx.DecryptFrame(hdr, enc[wire.FrameHeaderLen:], &out)
		if err != nil || ft != wire.FramePadding || len(p) != 0 {
			t.Fatalf("noInner=%v: skippable 应当 Padding 盲丢, got ft=%#x len=%d err=%v", noInner, byte(ft), len(p), err)
		}
		// critical 0x0B → ParseHeader 拒(fail-loud)。
		var enc2 []byte
		if _, err := tx.EncryptFrameInto(wire.FrameType(0x0B), []byte("x"), &enc2); err != nil {
			t.Fatal(err)
		}
		if _, err := wire.ParseHeader(enc2[:wire.FrameHeaderLen]); err != wire.ErrUnknownFrameType {
			t.Fatalf("noInner=%v: critical 未知应 ErrUnknownFrameType, got %v", noInner, err)
		}
	}
}

// TestSessionCtrExhaustion 证 tx ctr > 0xF000_0000 → ErrCtrExhaustion(防 nonce 空间耗尽)。
func TestSessionCtrExhaustion(t *testing.T) {
	k, n := testKeyNonce(0x44)
	tx := SessionTx{key: k, nonceBase: n, ctr: ctrExhaustionBound + 1, noInnerAEAD: true}
	var enc []byte
	if _, err := tx.EncryptFrameInto(wire.FrameTCPData, []byte("x"), &enc); !errors.Is(err, ErrCtrExhaustion) {
		t.Fatalf("应 ErrCtrExhaustion, got %v", err)
	}
}

// TestSessionPayloadTooLong 证 payload > MaxPayloadLen → ErrPayloadTooLong(AEAD 路 len 须 ≤ u16::MAX-tag)。
func TestSessionPayloadTooLong(t *testing.T) {
	k, n := testKeyNonce(0x55)
	tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: true}
	big := make([]byte, wire.MaxPayloadLen+1)
	var enc []byte
	if _, err := tx.EncryptFrameInto(wire.FrameTCPData, big, &enc); !errors.Is(err, ErrPayloadTooLong) {
		t.Fatalf("应 ErrPayloadTooLong, got %v", err)
	}
}

// TestSessionTamper 证伪装路 ciphertext 篡改 → AEAD open 失败 → ErrAEAD(完整性校验真起作用)。
func TestSessionTamper(t *testing.T) {
	k, n := testKeyNonce(0x66)
	tx := SessionTx{key: k, nonceBase: n, noInnerAEAD: false}
	rx := SessionRx{key: k, nonceBase: n, noInnerAEAD: false}

	var enc []byte
	if _, err := tx.EncryptFrameInto(wire.FrameTCPData, []byte("integrity"), &enc); err != nil {
		t.Fatal(err)
	}
	enc[wire.FrameHeaderLen+2] ^= 0xff // 翻转密文一字节(body 偏移 2,在 ciphertext 内)
	hdr, _ := wire.ParseHeader(enc[:wire.FrameHeaderLen])
	var out []byte
	if _, _, err := rx.DecryptFrame(hdr, enc[wire.FrameHeaderLen:], &out); !errors.Is(err, ErrAEAD) {
		t.Fatalf("应 ErrAEAD, got %v", err)
	}
}
