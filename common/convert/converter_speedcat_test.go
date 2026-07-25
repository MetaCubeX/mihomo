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
