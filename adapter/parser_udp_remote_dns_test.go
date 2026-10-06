package adapter

import (
	"testing"
)

func TestParseUDPRemoteDNS(t *testing.T) {
	for _, value := range []any{nil, true, false} {
		mapping := map[string]any{"type": "socks5", "name": "remote", "server": "127.0.0.1", "port": 1080, "udp": true}
		if value != nil {
			mapping["udp-remote-dns"] = value
		}
		enabled := value == true
		proxy, err := ParseProxy(mapping)
		if err != nil {
			t.Fatal(err)
		}
		defer proxy.Close()
		if want := enabled; proxy.ProxyInfo().UDPRemoteDNS != want {
			t.Fatalf("option not decoded: %v", enabled)
		}
	}
	if _, err := ParseProxy(map[string]any{"type": "socks5", "udp-remote-dns": "true"}); err == nil {
		t.Fatal("string flag must be rejected; use a YAML boolean")
	}
	// Unsupported protocols and incompatible encodings remain usable with remote DNS disabled.
	for _, kind := range []string{"direct", "reject", "dns", "vmess", "vless"} {
		proxy, err := ParseProxy(map[string]any{
			"type": kind, "name": "unsupported", "udp-remote-dns": true,
			"server": "127.0.0.1", "port": 1080, "uuid": "00000000-0000-0000-0000-000000000001",
			"cipher": "auto", "alterId": 0, "packet-encoding": "packetaddr",
		})
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", kind, err)
		}
		if proxy.ProxyInfo().UDPRemoteDNS {
			t.Fatalf("%s enabled unsupported remote DNS", kind)
		}
		proxy.Close()
	}
	// Disabling the option stays valid for every protocol.
	proxy, err := ParseProxy(map[string]any{"type": "direct", "name": "disabled", "udp-remote-dns": false})
	if err != nil {
		t.Fatalf("disabled option was rejected: %v", err)
	}
	proxy.Close()
}
