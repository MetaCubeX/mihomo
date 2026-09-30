package listener

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	IN "github.com/metacubex/mihomo/listener/inbound"
)

func TestParseListenerTunDefaultsToMips(t *testing.T) {
	listener, err := ParseListener(map[string]any{
		"type": "tun",
		"name": "tun-test",
	})
	if err != nil {
		t.Fatalf("parse listener: %v", err)
	}

	config, ok := listener.Config().(*IN.TunOption)
	if !ok {
		t.Fatalf("unexpected config type %T", listener.Config())
	}
	if config.Stack != C.TunMips {
		t.Fatalf("default tun stack = %s, want %s", config.Stack, C.TunMips)
	}
}
