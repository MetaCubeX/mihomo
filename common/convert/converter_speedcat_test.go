package convert

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestConvertsV2RaySpeedcat —— speedcat:// 订阅链接 → outbound map(docs/08 §4;4-switch fork 第 4 件)。
// userinfo = base64url("chacha20-poly1305:<psk_hex>");transport/sni/insecure/#name 全显式。
func TestConvertsV2RaySpeedcat(t *testing.T) {
	const psk = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" // 32B = 64 hex
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-poly1305:" + psk))
	uri := "speedcat://" + userinfo + "@hk.example.com:8443?transport=tcp&sni=hk.example.com&insecure=1#HK-Speedcat"
	sub := base64.StdEncoding.EncodeToString([]byte(uri)) // 订阅常整体 base64

	proxies, err := ConvertsV2Ray([]byte(sub))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("want 1 proxy, got %d (%v)", len(proxies), proxies)
	}
	p := proxies[0]
	for k, want := range map[string]string{
		"type": "speedcat", "server": "hk.example.com", "port": "8443",
		"password": psk, "transport": "tcp", "sni": "hk.example.com", "name": "HK-Speedcat",
	} {
		if got, ok := p[k].(string); !ok || got != want {
			t.Errorf("%s=%v want %s", k, p[k], want)
		}
	}
	if v, ok := p["skip-cert-verify"].(bool); !ok || !v {
		t.Errorf("skip-cert-verify=%v want true", p["skip-cert-verify"])
	}
	if v, ok := p["udp"].(bool); !ok || !v {
		t.Errorf("udp=%v want true", p["udp"])
	}
}

// TestConvertsV2RaySpeedcatDefaults —— 缺省 transport(tcp)/ sni(=host)/ insecure(false)/ name(host:port)。
func TestConvertsV2RaySpeedcatDefaults(t *testing.T) {
	const psk = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-poly1305:" + psk))
	uri := "speedcat://" + userinfo + "@1.2.3.4:443"
	sub := base64.StdEncoding.EncodeToString([]byte(uri))

	proxies, err := ConvertsV2Ray([]byte(sub))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	p := proxies[0]
	if p["transport"] != "tcp" {
		t.Errorf("transport default=%v want tcp", p["transport"])
	}
	if p["sni"] != "1.2.3.4" {
		t.Errorf("sni default=%v want 1.2.3.4", p["sni"])
	}
	if v, ok := p["skip-cert-verify"].(bool); ok && v {
		t.Errorf("insecure default should be false, got %v", p["skip-cert-verify"])
	}
	if p["name"] != "1.2.3.4:443" {
		t.Errorf("name default=%v want 1.2.3.4:443", p["name"])
	}
}

// TestConvertsV2RaySpeedcatBadMethod —— 不支持的 method → 静默丢(整条订阅空 → format invalid error,§4)。
func TestConvertsV2RaySpeedcatBadMethod(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:00112233445566778899aabbccddeeff"))
	uri := "speedcat://" + userinfo + "@1.2.3.4:443"
	sub := base64.StdEncoding.EncodeToString([]byte(uri))
	if _, err := ConvertsV2Ray([]byte(sub)); err == nil {
		t.Fatal("want format-invalid error for unsupported method")
	}
}

// TestConvertsV2RaySpeedcatUrlSafeAlphabet —— userinfo = base64url(RawURLEncoding),须用 decodeUrlSafe
// (base64.RawURLEncoding)解,不能退化回原串。锁易踩坑:std base64 遇 -/_ 会失败。
func TestConvertsV2RaySpeedcatUrlSafeAlphabet(t *testing.T) {
	const psk = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	decoded := "chacha20-poly1305:" + psk
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(decoded))
	// round-trip 证 decodeUrlSafe(base64url)通路通(即使本例未含 -/_ 也是回归保护)。
	if back := decodeUrlSafe(strings.TrimRight(userinfo, "=")); back != decoded {
		t.Fatalf("base64url round-trip failed: got %q want %q", back, decoded)
	}
	uri := "speedcat://" + userinfo + "@1.2.3.4:443"
	sub := base64.StdEncoding.EncodeToString([]byte(uri))
	proxies, err := ConvertsV2Ray([]byte(sub))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if proxies[0]["password"] != psk {
		t.Errorf("password=%v want %s", proxies[0]["password"], psk)
	}
}

// TestConvertsV2RaySpeedcatReality —— speedcat:// reality 订阅 → outbound map(阶段三 L3;ADR-013)。
// disguise=reality + transport=reality + spub(43 base64url)+ sid(11 base64url)→ reality-pubkey/reality-short-id emit。
// spub/sid 两端 base64url(非 mihomo 原生 REALITY 的 hex,ADR-013)。
func TestConvertsV2RaySpeedcatReality(t *testing.T) {
	const psk = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-poly1305:" + psk))
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i + 1) // 1..32(避开前导 0x00;converter 仅字符串透传,不做密码学校验)
	}
	spub := base64.RawURLEncoding.EncodeToString(pub[:])
	var sid [8]byte
	for i := range sid {
		sid[i] = byte(i) // 0..7 → base64url "AAECAwQFBgc"
	}
	sidB64 := base64.RawURLEncoding.EncodeToString(sid[:])
	uri := "speedcat://" + userinfo + "@hk.example.com:8443?disguise=reality&transport=reality&sni=dest.example.com&spub=" + spub + "&sid=" + sidB64 + "#HK-Reality"
	sub := base64.StdEncoding.EncodeToString([]byte(uri))

	proxies, err := ConvertsV2Ray([]byte(sub))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("want 1 proxy, got %d (%v)", len(proxies), proxies)
	}
	p := proxies[0]
	for k, want := range map[string]string{
		"type": "speedcat", "server": "hk.example.com", "port": "8443",
		"password": psk, "transport": "reality", "sni": "dest.example.com",
		"name": "HK-Reality", "reality-pubkey": spub,
	} {
		if got, ok := p[k].(string); !ok || got != want {
			t.Errorf("%s=%v want %s", k, p[k], want)
		}
	}
	// reality-short-id 现 emit 为 []string(多 sid 列表;单 sid 也出切片形态,ADR-013)。
	sids, ok := p["reality-short-id"].([]string)
	if !ok {
		t.Fatalf("reality-short-id=%v want []string", p["reality-short-id"])
	}
	if len(sids) != 1 || sids[0] != sidB64 {
		t.Errorf("reality-short-id=%v want [%s]", sids, sidB64)
	}
	if v, ok := p["udp"].(bool); !ok || !v {
		t.Errorf("udp=%v want true", p["udp"])
	}
}

// TestConvertsV2RaySpeedcatRealityMultiSid —— speedcat:// sid 多值(sid=a&sid=b&sid=c)→
// reality-short-id emit 为完整 []string(顺序保留;client 取首算 AuthKey,余供轮换/撤销,ADR-013)。
func TestConvertsV2RaySpeedcatRealityMultiSid(t *testing.T) {
	const psk = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-poly1305:" + psk))
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	spub := base64.RawURLEncoding.EncodeToString(pub[:])
	// 三条 base64url 11 字符 short_id(各 8B,0..7 / 10..17 / 20..27)。
	mkSid := func(off byte) string {
		var b [8]byte
		for i := range b {
			b[i] = off + byte(i)
		}
		return base64.RawURLEncoding.EncodeToString(b[:])
	}
	a, b2, c := mkSid(0), mkSid(10), mkSid(20)
	uri := "speedcat://" + userinfo + "@hk.example.com:8443?disguise=reality&transport=reality&spub=" + spub +
		"&sid=" + a + "&sid=" + b2 + "&sid=" + c + "#HK-Reality"
	sub := base64.StdEncoding.EncodeToString([]byte(uri))

	proxies, err := ConvertsV2Ray([]byte(sub))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	p := proxies[0]
	sids, ok := p["reality-short-id"].([]string)
	if !ok {
		t.Fatalf("reality-short-id=%v want []string", p["reality-short-id"])
	}
	want := []string{a, b2, c}
	if len(sids) != len(want) {
		t.Fatalf("reality-short-id len=%d want %d (%v)", len(sids), len(want), sids)
	}
	for i := range want {
		if sids[i] != want[i] {
			t.Errorf("reality-short-id[%d]=%q want %q", i, sids[i], want[i])
		}
	}
}

// TestConvertsV2RaySpeedcatRealityImpliedTransport —— 只写 disguise=reality(不写 transport)→
// converter 单点提升 transport=reality(URI disguise 标识 ↔ fork transport=kind 错位对齐)。
func TestConvertsV2RaySpeedcatRealityImpliedTransport(t *testing.T) {
	const psk = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-poly1305:" + psk))
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	spub := base64.RawURLEncoding.EncodeToString(pub[:])
	var sid [8]byte
	for i := range sid {
		sid[i] = byte(i)
	}
	sidB64 := base64.RawURLEncoding.EncodeToString(sid[:])
	uri := "speedcat://" + userinfo + "@hk.example.com:8443?disguise=reality&spub=" + spub + "&sid=" + sidB64
	sub := base64.StdEncoding.EncodeToString([]byte(uri))

	proxies, err := ConvertsV2Ray([]byte(sub))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	p := proxies[0]
	if p["transport"] != "reality" {
		t.Errorf("transport=%v want reality(disguise=reality 应提升)", p["transport"])
	}
	if p["reality-pubkey"] != spub {
		t.Errorf("reality-pubkey=%v want %s", p["reality-pubkey"], spub)
	}
}
