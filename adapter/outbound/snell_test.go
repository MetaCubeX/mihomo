package outbound

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

func TestNewSnellUserKey(t *testing.T) {
	var option SnellOption
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	mapping := map[string]any{
		"name":    "snell-v6",
		"server":  "127.0.0.1",
		"port":    443,
		"psk":     "0123456789ab",
		"version": 6,
		"userkey": "alice-key",
	}
	if err := decoder.Decode(mapping, &option); err != nil {
		t.Fatal(err)
	}

	proxy, err := NewSnell(option)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(proxy.userKey); got != option.UserKey {
		t.Fatalf("userkey = %q, want %q", got, option.UserKey)
	}
}

func TestNewSnellUserKeyValidation(t *testing.T) {
	base := SnellOption{
		Name:    "snell",
		Server:  "127.0.0.1",
		Port:    443,
		Psk:     "0123456789ab",
		Version: 6,
		UserKey: "alice-key",
	}

	t.Run("v6 only", func(t *testing.T) {
		option := base
		option.Version = 4
		if _, err := NewSnell(option); err == nil || !strings.Contains(err.Error(), "only supported on version 6") {
			t.Fatalf("expected v6-only error, got %v", err)
		}
	})

	t.Run("maximum length", func(t *testing.T) {
		option := base
		option.UserKey = strings.Repeat("k", 256)
		if _, err := NewSnell(option); err == nil || !strings.Contains(err.Error(), "at most 255 bytes") {
			t.Fatalf("expected userkey length error, got %v", err)
		}
	})
}
