// reality_auth_test.go —— Reality 身份层 stealth auth KAT(跨实现字节对齐) + roundtrip + 边界拒。
//
// **核心 TestRealityAuth_KAT:** 与 Rust reality_auth.rs::kat_ground_truth 共享同款固定输入
// (逐字节复刻 fixtures()),断言 Go ClientEncode 产出的 sessionId 密文 + AuthKey 与 Rust 真值
// **逐字节一致**。这是两端能互通的硬证据 —— 任一字节布局漂移(random 劈半 / HKDF salt-ikm 顺序 /
// GCM nonce 取段 / AuthPayload 字段序)→ KAT 立刻红。
//
// 重跑取真值:`cargo test -p proto-core reality_auth::tests::kat_ground_truth -- --nocapture`
// 抄 hex 回 KATserverPub/ephPub/sessionCT/authKey(回冻 Rust reality_auth.rs 为 assert_eq 同款向量)。
//
// 复用 crypto_test.go::mustHex + dh_test.go::hex32(同包 _test.go 间共享 helper)。

package crypto

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// realityFixtures 返回逐字节复刻 Rust reality_auth.rs::fixtures() 的固定输入。
// 改前先重跑 Rust kat_ground_truth 取新 hex 抄回(两端同步)。
func realityFixtures(t *testing.T) (serverPriv, serverPub, ephPriv, ephPub, random [KeyLen]byte, payload AuthPayload) {
	t.Helper()
	serverPriv = hex32(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	serverPub = hex32(t, "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c")
	ephPriv = hex32(t, "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
	ephPub = hex32(t, "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b")
	random = hex32(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	// short_id = seq(0xb0) → b0..b7(对照 Rust short_id: seq(0xb0))。
	var sid [ShortIDLen]byte
	copy(sid[:], mustHex(t, "b0b1b2b3b4b5b6b7"))
	payload = AuthPayload{Version: AuthVersion, Time: 0x12345678, ShortID: sid}
	return
}

// TestRealityAuth_KAT 跨实现字节对齐铁证(核心 DoD):Go ClientEncode == Rust 真值。
// 任一端字节布局漂移 → 此处红。
func TestRealityAuth_KAT(t *testing.T) {
	_, serverPub, ephPriv, ephPub, random, payload := realityFixtures(t)
	aad := []byte("speedcat-reality-aad")

	ct, authKey, err := ClientEncode(serverPub, ephPriv, random, payload, aad)
	if err != nil {
		t.Fatalf("ClientEncode: %v", err)
	}

	// Rust kat_ground_truth 印出的真值(逐字节抄回)。
	wantCT := hex32(t, "dea5d2085cc36ca3ef6d5c63b468c2de9fbaf8257fc848d7bd651477765d53fd")
	wantKey := hex32(t, "02081137cf0207838e853b1c457d10aaf9f26eeb08a6b44b9305804ebad5983c")

	if !bytes.Equal(ct[:], wantCT[:]) {
		t.Fatalf("session_ct KAT 不符(跨实现字节漂移):\n got %x\nwant %x", ct[:], wantCT[:])
	}
	if !bytes.Equal(authKey[:], wantKey[:]) {
		t.Fatalf("auth_key KAT 不符(跨实现字节漂移):\n got %x\nwant %x", authKey[:], wantKey[:])
	}

	// eph 公钥派生一致性:锁「公钥 = X25519(priv, Basepoint)」,与 fixtures ephPub 一致。
	// (DhKeypair{secret:…} 字面量不自动派生 public —— 须直接 curve25519.X25519。)
	derivedPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519(ephPriv, Basepoint): %v", err)
	}
	if !bytes.Equal(derivedPub, ephPub[:]) {
		t.Fatalf("eph 公钥派生与 KAT ephPub 不符:\n got %x\nwant %x", derivedPub, ephPub[:])
	}
}

// TestRealityAuth_Roundtrip 客户端 seal ↔ 服务端 open 还原 + 两端 AuthKey 一致(DH 对称)。
// 对照 Rust client_server_roundtrip。
func TestRealityAuth_Roundtrip(t *testing.T) {
	serverPriv, serverPub, ephPriv, ephPub, random, payload := realityFixtures(t)
	aad := []byte("speedcat-reality-aad")

	ct, clientKey, err := ClientEncode(serverPub, ephPriv, random, payload, aad)
	if err != nil {
		t.Fatalf("ClientEncode: %v", err)
	}
	decoded, serverKey, err := ServerDecode(serverPriv, ephPub, random, ct, aad)
	if err != nil {
		t.Fatalf("ServerDecode: %v", err)
	}

	if decoded != payload {
		t.Fatalf("payload roundtrip 失败:\n got %+v\nwant %+v", decoded, payload)
	}
	if !bytes.Equal(clientKey[:], serverKey[:]) {
		t.Fatalf("两端 AuthKey 不一致(DH 应对称)")
	}
	if len(ct) != SessionCTLen {
		t.Fatalf("ct 长度 = %d, want %d", len(ct), SessionCTLen)
	}
}

// TestRealityAuth_Deterministic 同输入 → 同输出(确定性;为跨实现 KAT 铺路的前提)。
// 对照 Rust deterministic。
func TestRealityAuth_Deterministic(t *testing.T) {
	_, serverPub, ephPriv, _, random, payload := realityFixtures(t)
	aad := []byte("speedcat-reality-aad")

	ct1, k1, err := ClientEncode(serverPub, ephPriv, random, payload, aad)
	if err != nil {
		t.Fatalf("ClientEncode #1: %v", err)
	}
	ct2, k2, err := ClientEncode(serverPub, ephPriv, random, payload, aad)
	if err != nil {
		t.Fatalf("ClientEncode #2: %v", err)
	}
	if !bytes.Equal(ct1[:], ct2[:]) {
		t.Fatalf("seal 非确定性")
	}
	if !bytes.Equal(k1[:], k2[:]) {
		t.Fatalf("AuthKey 非确定性")
	}
}

// TestRealityAuth_Rejects 坏 AAD / 篡改密文 / 错密钥 / 低序点公钥 → ServerDecode/open 失败
// (对照 Rust open_rejects_* + derive_rejects_low_order)。任一失败 → 调用方据此转发 dest。
func TestRealityAuth_Rejects(t *testing.T) {
	serverPriv, serverPub, ephPriv, ephPub, random, payload := realityFixtures(t)
	aad := []byte("speedcat-reality-aad")

	ct, _, err := ClientEncode(serverPub, ephPriv, random, payload, aad)
	if err != nil {
		t.Fatalf("ClientEncode: %v", err)
	}

	t.Run("bad_aad", func(t *testing.T) {
		// 探测者篡改 CH → AAD 变 → open 必失败。
		badAAD := []byte("speedcat-reality-TAMPERED")
		if _, _, err := ServerDecode(serverPriv, ephPub, random, ct, badAAD); err == nil {
			t.Fatal("坏 AAD 应失败,却成功")
		}
	})

	t.Run("tampered_ct", func(t *testing.T) {
		var tampered [SessionCTLen]byte
		copy(tampered[:], ct[:])
		tampered[0] ^= 0xff // 翻转首字节 → GCM 完整性失败。
		if _, _, err := ServerDecode(serverPriv, ephPub, random, tampered, aad); err == nil {
			t.Fatal("篡改密文应失败,却成功")
		}
	})

	t.Run("wrong_eph_pub", func(t *testing.T) {
		// 用第三个无关密钥对的 eph_pub 去 decode → AuthKey 不同 → open 失败(无凭据探测者场景)。
		otherEph := hex32(t, "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60")
		if _, _, err := ServerDecode(serverPriv, otherEph, random, ct, aad); err == nil {
			t.Fatal("错 eph_pub 应失败,却成功")
		}
	})

	t.Run("low_order_pub", func(t *testing.T) {
		// peer_pub 全零 → contributory 校验拒(防小子群;对照 dh.go)。
		zeroPub := [KeyLen]byte{}
		if _, err := DeriveSharedSecret(serverPriv, zeroPub); err == nil {
			t.Fatal("低序/全零公钥应失败,却成功")
		}
	})
}

// TestRealityAuth_ValidateGates version / time 窗口 / short_id 白名单三关(对照 Rust validate_gates)。
func TestRealityAuth_ValidateGates(t *testing.T) {
	var sid [ShortIDLen]byte
	copy(sid[:], mustHex(t, "b0b1b2b3b4b5b6b7"))
	allowed := [][ShortIDLen]byte{sid}
	now := uint32(0x12345678)

	ok := AuthPayload{Version: AuthVersion, Time: now, ShortID: sid}
	if !ok.Validate(now, allowed) {
		t.Fatal("全过应通过")
	}

	// 坏 version。
	badVer := ok
	badVer.Version = AuthVersion + 1
	if badVer.Validate(now, allowed) {
		t.Fatal("坏 version 应拒")
	}

	// time 超窗(±MaxTimeDiffSecs 之外)。
	badTime := ok
	badTime.Time = now + uint32(MaxTimeDiffSecs) + 5
	if badTime.Validate(now, allowed) {
		t.Fatal("time 超窗应拒")
	}

	// short_id 不在白名单。
	badSid := ok
	copy(badSid.ShortID[:], mustHex(t, "c0c1c2c3c4c5c6c7"))
	if badSid.Validate(now, allowed) {
		t.Fatal("short_id 不在白名单应拒")
	}

	// time 窗口边界内仍过(恰 +MaxTimeDiffSecs)。
	edge := ok
	edge.Time = now + uint32(MaxTimeDiffSecs)
	if !edge.Validate(now, allowed) {
		t.Fatal("time 边界(+MaxTimeDiffSecs)应通过")
	}
}

// TestRealityAuth_PayloadBytes ToBytes / FromBytes roundtrip + 16B 布局钉死(对照 Rust payload_bytes_roundtrip)。
func TestRealityAuth_PayloadBytes(t *testing.T) {
	var sid [ShortIDLen]byte
	copy(sid[:], mustHex(t, "9999999999999999"))
	p := AuthPayload{Version: 0x01, Time: 0xdeadbeef, ShortID: sid}

	b := p.ToBytes()
	if len(b) != SessionPTLen {
		t.Fatalf("len = %d, want %d", len(b), SessionPTLen)
	}
	if b[0] != 0x01 {
		t.Fatalf("ver[0] = %x, want 01", b[0])
	}
	if !bytes.Equal(b[1:4], []byte{0, 0, 0}) {
		t.Fatalf("reserved[1:4] = %x, want 000000", b[1:4])
	}
	wantTime := []byte{0xde, 0xad, 0xbe, 0xef}
	if !bytes.Equal(b[4:8], wantTime) {
		t.Fatalf("time[4:8] = %x, want %x(BE)", b[4:8], wantTime)
	}
	if !bytes.Equal(b[8:16], sid[:]) {
		t.Fatalf("short_id[8:16] 不符")
	}

	roundTrip := AuthPayloadFromBytes(b)
	if roundTrip != p {
		t.Fatalf("FromBytes roundtrip 失败:\n got %+v\nwant %+v", roundTrip, p)
	}
}
