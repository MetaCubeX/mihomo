// Package outbound · speedcat reality outbound 构造测试(4-switch fork 第 2 件;L3 阶段三,2026-07-24)。
//
// 验证 `speedcat sub gen` 产物(YAML 里的 transport: reality + reality-pubkey/reality-short-id)
// 经 NewSpeedcat 能装配出可用 outbound —— 即 decodeRealityPubKey/decodeRealityShortID 两道
// base64url 解码注入 transport.Config 的 reality arm 真活(fail-loud:缺/错 → error)。
// NewSpeedcat 仅装配(握手延后到首次 Dial),故本测试零网络、纯构造。
// 对照 adapter/mihomo/client/e2e_rust_test.go(跨实现 reality 拨号铁证)—— 那是拨号层,
// 本测试是订阅→outbound 装配层(L3 新增的 fork 侧 wiring)。
package outbound

import (
	"testing"
)

// validPSK 是 speedcat genkey 出的 64 hex(非生产;仅测试装配,不拨号)。
const validPSK = "83d7cbcbc0b3c8ea9184a7f4c66e2f36778bab6316e49999fefcae1e8c4fb940"

// 这组 reality 值与 `speedcat sub gen --format yaml` 的产物逐字段一致
// (privkey COJccE4n4zgEMeOHaTUI6EmdV71kNDvBhve0JH3esSQ → pubkey PRsKN9bB...;
// short_id AAECAwQFBgc = 8B base64url)。锁订阅产物 ↔ fork 装配的端到端契约。
const (
	genPubKey  = "PRsKN9bB3UvViwA8Zr6XDN9pB42EEKY0APIfFD1LWlg" // base64url 43 字符 = 32B
	genShortID = "AAECAwQFBgc"                                 // base64url 11 字符 = 8B
)

// TestNewSpeedcatRealityConstructs:订阅 YAML 的 reality 节点经 NewSpeedcat 装配成功。
// 覆盖 plan 验收 step 3(fork outbound 构造):decodeRealityPubKey/decodeRealityShortID
// 两道 base64url 解码都过 → transport.Config 注入 reality 公钥 + short_id → client.NewClient(KindReality)。
func TestNewSpeedcatRealityConstructs(t *testing.T) {
	opt := SpeedcatOption{
		Name:            "hk.example.com:443",
		Server:          "hk.example.com",
		Port:            443,
		Password:        validPSK,
		SNI:             "cloudflare.com",
		Transport:       "reality",
		RealityPubKey:   genPubKey,
		RealityShortIDs: []string{genShortID},
	}
	s, err := NewSpeedcat(opt)
	if err != nil {
		t.Fatalf("NewSpeedcat(reality) 不该报错(订阅产物应能装配):%v", err)
	}
	if s == nil {
		t.Fatal("NewSpeedcat(reality) 返回 nil outbound")
	}
	if !s.SupportUDP() {
		// udp 透传由 option.UDP 决定;此处未设 → false 合理。这里只断言构造本身成功。
		t.Log("注意:option 未设 UDP(订阅 YAML 设 udp:true 才 SupportUDP);构造本身已成功")
	}
}

// TestNewSpeedcatRealityMissingPubKeyFailLoud:reality 缺 pubkey → fail-loud(返 error)。
// 锁 §6.1 fail-loud 契约:无法注入 auth → 拒构造,不静默降级(否则握手必被转发 dest,假绿)。
func TestNewSpeedcatRealityMissingPubKeyFailLoud(t *testing.T) {
	opt := SpeedcatOption{
		Name:            "x",
		Server:          "hk.example.com",
		Port:            443,
		Password:        validPSK,
		Transport:       "reality",
		RealityShortIDs: []string{genShortID}, // 有 short_id 但缺 pubkey
	}
	if _, err := NewSpeedcat(opt); err == nil {
		t.Fatal("reality 缺 reality-pubkey 应 fail-loud 报错,实际 nil")
	}
}

// TestNewSpeedcatRealityBadShortIDFailLoud:reality short_id 长度错 → fail-loud。
// 锁 decodeRealityShortID 的 8B 长度校验(防订阅写错 base64url 静默装配坏值)。
func TestNewSpeedcatRealityBadShortIDFailLoud(t *testing.T) {
	opt := SpeedcatOption{
		Name:            "x",
		Server:          "hk.example.com",
		Port:            443,
		Password:        validPSK,
		Transport:       "reality",
		RealityPubKey:   genPubKey,
		RealityShortIDs: []string{"AAECAw"}, // 3B 非 8B → 解码后长度错
	}
	if _, err := NewSpeedcat(opt); err == nil {
		t.Fatal("reality short_id 长度错(非 8B)应 fail-loud 报错,实际 nil")
	}
}

// TestNewSpeedcatRealityEmptyShortIDFailLoud:reality short_id 列表空 → fail-loud(ADR-013 多 sid)。
// 锁 fail-loud 契约:RealityShortIDs 为空切片时 NewSpeedcat 拒构造(client 算 AuthKey 需至少一个 sid)。
func TestNewSpeedcatRealityEmptyShortIDFailLoud(t *testing.T) {
	opt := SpeedcatOption{
		Name:          "x",
		Server:        "hk.example.com",
		Port:          443,
		Password:      validPSK,
		Transport:     "reality",
		RealityPubKey: genPubKey,
		// RealityShortIDs 故意留空(切片 nil)。
	}
	if _, err := NewSpeedcat(opt); err == nil {
		t.Fatal("reality 缺 reality-short-id(空列表)应 fail-loud 报错,实际 nil")
	}
}

// TestNewSpeedcatRealityMultiSidConstructs:多 sid 列表 → 装配成功(client 取首个算 AuthKey,
// 余供轮换/逐用户撤销,ADR-013)。订阅产物(sub gen --format yaml 出多 sid 列表)经此构造通。
func TestNewSpeedcatRealityMultiSidConstructs(t *testing.T) {
	opt := SpeedcatOption{
		Name:            "hk.example.com:443",
		Server:          "hk.example.com",
		Port:            443,
		Password:        validPSK,
		SNI:             "cloudflare.com",
		Transport:       "reality",
		RealityPubKey:   genPubKey,
		RealityShortIDs: []string{genShortID, "CgoMDA4PEBE", "EhMUFxgaGxw"}, // 多 sid 列表(首项 = genShortID)
	}
	s, err := NewSpeedcat(opt)
	if err != nil {
		t.Fatalf("NewSpeedcat(reality 多 sid) 不该报错(取首个 sid 装配):%v", err)
	}
	if s == nil {
		t.Fatal("NewSpeedcat(reality 多 sid) 返回 nil outbound")
	}
}
