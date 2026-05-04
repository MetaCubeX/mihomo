package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseTailscaleProxy(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":        "ts-main",
		"type":        "tailscale",
		"auth-key":    "tskey-auth-test",
		"hostname":    "ts-main",
		"control-url": "https://controlplane.tailscale.com",
		"ephemeral":   false,
		"exit-node":   "exit-gateway.example.ts.net",
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Name() != "ts-main" {
		t.Fatalf("unexpected proxy name: %s", proxy.Name())
	}
	if proxy.Type() != C.Tailscale {
		t.Fatalf("unexpected proxy type: %s", proxy.Type())
	}
	if !proxy.SupportUDP() {
		t.Fatal("tailscale proxy should advertise UDP support")
	}
}
