package listener

import (
	"path/filepath"
	"testing"

	IN "github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/require"
)

func TestParseUnixSocketListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mihomo.sock")

	tests := []struct {
		listenerType string
		extra        map[string]any
	}{
		{listenerType: "http"},
		{listenerType: "socks"},
		{listenerType: "mixed"},
		{listenerType: "shadowsocks", extra: map[string]any{"cipher": "aes-128-gcm", "password": "test"}},
		{listenerType: "snell", extra: map[string]any{"psk": "test"}},
		{listenerType: "vmess", extra: map[string]any{"users": []map[string]any{{"uuid": "00000000-0000-0000-0000-000000000000"}}}},
		{listenerType: "trojan", extra: map[string]any{"users": []map[string]any{{"password": "test"}}}},
		{listenerType: "anytls"},
		{listenerType: "sudoku", extra: map[string]any{"key": "test"}},
		{listenerType: "tunnel", extra: map[string]any{"network": []string{"tcp"}, "target": "127.0.0.1:80"}},
		{listenerType: "trusttunnel", extra: map[string]any{"certificate": "test", "private-key": "test"}},
		{listenerType: "hysteria2-realm", extra: map[string]any{"token": "test"}},
	}

	for _, tt := range tests {
		t.Run(tt.listenerType, func(t *testing.T) {
			mapping := map[string]any{
				"name": "unix-in",
				"type": tt.listenerType,
				"port": path,
			}
			for key, value := range tt.extra {
				mapping[key] = value
			}
			l, err := ParseListener(mapping)
			require.NoError(t, err)
			require.Equal(t, path, l.RawAddress())

			switch config := l.Config().(type) {
			case *IN.SocksOption:
				require.False(t, config.UDP)
			case *IN.MixedOption:
				require.False(t, config.UDP)
			case *IN.ShadowSocksOption:
				require.False(t, config.UDP)
			}
		})
	}
}

func TestParseUnixSocketListenerRejectsUDP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mihomo.sock")
	for _, listenerType := range []string{"socks", "mixed", "shadowsocks"} {
		mapping := map[string]any{
			"name": "unix-in",
			"type": listenerType,
			"port": path,
			"udp":  true,
		}
		if listenerType == "shadowsocks" {
			mapping["cipher"] = "aes-128-gcm"
			mapping["password"] = "test"
		}
		_, err := ParseListener(mapping)
		require.ErrorContains(t, err, "udp cannot be used")
	}
}

func TestParseUnixSocketListenerRejectsUnsupportedType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mihomo.sock")
	tests := []struct {
		listenerType string
		extra        map[string]any
	}{
		{listenerType: "redir"},
		{listenerType: "tproxy"},
		{listenerType: "tun"},
		{listenerType: "vless", extra: map[string]any{"users": []map[string]any{{"uuid": "00000000-0000-0000-0000-000000000000"}}}},
		{listenerType: "mieru", extra: map[string]any{"transport": "TCP", "users": map[string]string{"test": "test"}}},
		{listenerType: "tuic", extra: map[string]any{"certificate": "test", "private-key": "test"}},
		{listenerType: "hysteria2", extra: map[string]any{"certificate": "test", "private-key": "test"}},
		{listenerType: "shadowquic", extra: map[string]any{"jls-upstream": map[string]any{"addr": "127.0.0.1:443"}}},
	}
	for _, tt := range tests {
		t.Run(tt.listenerType, func(t *testing.T) {
			mapping := map[string]any{
				"name": "unix-in",
				"type": tt.listenerType,
				"port": path,
			}
			for key, value := range tt.extra {
				mapping[key] = value
			}
			_, err := ParseListener(mapping)
			require.ErrorContains(t, err, "not supported")
		})
	}
}

func TestParseUnixSocketListenerRejectsPacketTransports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mihomo.sock")
	tests := []map[string]any{
		{"type": "shadowsocks", "cipher": "aes-128-gcm", "password": "test", "kcp-tun": map[string]any{"enable": true}},
		{"type": "vmess", "users": []map[string]any{{"uuid": "00000000-0000-0000-0000-000000000000"}}, "mkcp-config": map[string]any{"enable": true}},
		{"type": "tunnel", "network": []string{"udp"}, "target": "127.0.0.1:80"},
		{"type": "trusttunnel", "certificate": "test", "private-key": "test", "network": []string{"tcp", "udp"}},
	}
	for _, mapping := range tests {
		mapping["name"] = "unix-in"
		mapping["port"] = path
		_, err := ParseListener(mapping)
		require.ErrorContains(t, err, "cannot be used with a unix socket")
	}
}

func TestParseNumericListenerKeepsUDPDefault(t *testing.T) {
	l, err := ParseListener(map[string]any{
		"name": "socks-in",
		"type": "socks",
		"port": 0,
	})
	require.NoError(t, err)
	require.True(t, l.Config().(*IN.SocksOption).UDP)
}
