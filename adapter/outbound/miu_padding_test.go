package outbound_test

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
)

func TestMiuPaddingSchemeYAMLField(t *testing.T) {
	_, err := adapter.ParseProxy(map[string]any{
		"type":           "miu",
		"name":           "miu-padding",
		"server":         "127.0.0.1",
		"port":           443,
		"psk":            "miu-test-psk-alpha-2026",
		"padding-scheme": []any{"stop=2", "0=30-30", "1=128-160"},
	})
	if err != nil {
		t.Fatalf("valid padding-scheme was not accepted: %v", err)
	}
	base := map[string]any{
		"type":           "miu",
		"name":           "miu-padding",
		"server":         "127.0.0.1",
		"port":           443,
		"psk":            "miu-test-psk-alpha-2026",
		"padding-scheme": []any{"not-a-scheme"},
	}
	if _, err := adapter.ParseProxy(base); err == nil {
		t.Fatal("invalid padding-scheme was silently accepted")
	}
}
