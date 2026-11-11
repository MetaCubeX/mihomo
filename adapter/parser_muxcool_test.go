package adapter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProxyMuxCoolAndFragment(t *testing.T) {
	base := func(typ string, extra map[string]any) map[string]any {
		m := map[string]any{
			"name":   "test",
			"type":   typ,
			"server": "127.0.0.1",
			"port":   443,
			"uuid":   "b831381d-6324-4d53-ad4f-8cda48b30811",
		}
		switch typ {
		case "vmess":
			m["alterId"] = 0
			m["cipher"] = "auto"
		case "trojan":
			m["password"] = "password"
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	muxCool := map[string]any{"enabled": true, "concurrency": 4}

	for _, good := range []map[string]any{
		base("vless", map[string]any{"mux-cool": muxCool}),
		base("vmess", map[string]any{"mux-cool": muxCool}),
		base("vless", map[string]any{"mux-cool": muxCool, "smux": map[string]any{"enabled": false}}),
		base("vless", map[string]any{"fragment": map[string]any{"enabled": true}}),
		base("trojan", map[string]any{"fragment": map[string]any{"enabled": true, "packets": "1-3", "length": "10-20", "interval": 0}}),
		base("trojan", map[string]any{"mux-cool": map[string]any{"enabled": false}}),
		base("vless", map[string]any{"fragment": map[string]any{"enabled": false, "packets": "bad"}}),
	} {
		proxy, err := ParseProxy(good)
		require.NoError(t, err, "%v", good)
		assert.NoError(t, proxy.Close())
	}

	for _, bad := range []map[string]any{
		base("trojan", map[string]any{"mux-cool": muxCool}),
		base("vless", map[string]any{"mux-cool": muxCool, "flow": "xtls-rprx-vision", "tls": true}),
		base("vless", map[string]any{"mux-cool": muxCool, "smux": map[string]any{"enabled": true}}),
		base("vless", map[string]any{"fragment": map[string]any{"enabled": true, "packets": "bad"}}),
		base("vless", map[string]any{"fragment": map[string]any{"enabled": true, "length": "0"}}),
	} {
		_, err := ParseProxy(bad)
		assert.Error(t, err, "%v", bad)
	}
}
