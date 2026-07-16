package adapter

import (
	"reflect"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
)

func TestParseProxyMuxCoolConfigurations(t *testing.T) {
	tests := []struct {
		name                    string
		muxCool                 map[string]any
		wantWrapped             bool
		wantMaxConcurrency      int
		wantMaxConnections      int
		wantXUDPConcurrency     int
		wantXUDPProxyUDP443Mode string
	}{
		{name: "omitted"},
		{name: "disabled", muxCool: map[string]any{"enabled": false}},
		{
			name: "defaults", muxCool: map[string]any{"enabled": true}, wantWrapped: true,
			wantMaxConcurrency: 8, wantMaxConnections: 128, wantXUDPProxyUDP443Mode: "reject",
		},
		{
			name: "custom",
			muxCool: map[string]any{
				"enabled": true, "max-concurrency": 3, "max-connections": 19,
				"xudp-concurrency": 4, "xudp-proxy-udp443": "allow",
			},
			wantWrapped: true, wantMaxConcurrency: 3, wantMaxConnections: 19,
			wantXUDPConcurrency: 4, wantXUDPProxyUDP443Mode: "allow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapping := map[string]any{"name": "test", "type": "direct"}
			if tt.muxCool != nil {
				mapping["mux.cool"] = tt.muxCool
			}
			parsed, err := ParseProxy(mapping)
			if err != nil {
				t.Fatalf("ParseProxy: %v", err)
			}
			defer parsed.Close()
			wrapped := unwrapAutoClose(t, parsed.Adapter())
			muxCool, ok := wrapped.(*outbound.MuxCool)
			if ok != tt.wantWrapped {
				t.Fatalf("MuxCool wrapper present = %t, want %t (%T)", ok, tt.wantWrapped, wrapped)
			}
			if ok {
				options := muxCool.Options()
				if options.MaxConcurrency != tt.wantMaxConcurrency ||
					options.MaxConnections != tt.wantMaxConnections ||
					options.XUDPConcurrency != tt.wantXUDPConcurrency ||
					options.XUDPProxyUDP443 != tt.wantXUDPProxyUDP443Mode {
					t.Fatalf("options = %+v", options)
				}
			}
		})
	}
}

func TestParseProxyRejectsInvalidMuxCoolConfigurations(t *testing.T) {
	tests := []struct {
		name    string
		mapping map[string]any
		match   string
	}{
		{
			name:    "negative concurrency",
			mapping: map[string]any{"name": "test", "type": "direct", "mux.cool": map[string]any{"enabled": true, "max-concurrency": -1}},
			match:   "max-concurrency",
		},
		{
			name:    "negative connections",
			mapping: map[string]any{"name": "test", "type": "direct", "mux.cool": map[string]any{"enabled": true, "max-connections": -1}},
			match:   "max-connections",
		},
		{
			name:    "negative xudp concurrency",
			mapping: map[string]any{"name": "test", "type": "direct", "mux.cool": map[string]any{"enabled": true, "xudp-concurrency": -1}},
			match:   "xudp-concurrency",
		},
		{
			name:    "unknown udp 443 policy",
			mapping: map[string]any{"name": "test", "type": "direct", "mux.cool": map[string]any{"enabled": true, "xudp-proxy-udp443": "drop"}},
			match:   "xudp-proxy-udp443",
		},
		{
			name: "smux conflict",
			mapping: map[string]any{
				"name": "test", "type": "direct",
				"smux":     map[string]any{"enabled": true},
				"mux.cool": map[string]any{"enabled": true},
			},
			match: "cannot be enabled together",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseProxy(tt.mapping)
			if parsed != nil {
				_ = parsed.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tt.match) {
				t.Fatalf("error = %v, want substring %q", err, tt.match)
			}
		})
	}
}

func unwrapAutoClose(t *testing.T, adapter any) any {
	t.Helper()
	value := reflect.ValueOf(adapter)
	if value.Kind() != reflect.Pointer || value.Elem().Kind() != reflect.Struct {
		t.Fatalf("unexpected outer adapter %T", adapter)
	}
	field := value.Elem().FieldByName("ProxyAdapter")
	if !field.IsValid() || !field.CanInterface() {
		t.Fatalf("cannot unwrap outer adapter %T", adapter)
	}
	return field.Interface()
}
