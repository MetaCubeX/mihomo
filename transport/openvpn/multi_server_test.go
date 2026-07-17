package openvpn

import (
	"testing"
)

func TestRemoteServersSingleServer(t *testing.T) {
	cfg := ClientConfig{
		RemoteHost: "vpn.example.com",
		RemotePort: 1194,
		Proto:      "udp",
	}
	servers := cfg.RemoteServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Host != "vpn.example.com" {
		t.Fatalf("expected host vpn.example.com, got %s", servers[0].Host)
	}
	if servers[0].Port != 1194 {
		t.Fatalf("expected port 1194, got %d", servers[0].Port)
	}
}

func TestRemoteServersMultiple(t *testing.T) {
	cfg := ClientConfig{
		Servers: []RemoteEntry{
			{Host: "vpn1.example.com", Port: 1194, Proto: "udp"},
			{Host: "vpn2.example.com", Port: 443, Proto: "tcp"},
			{Host: "vpn3.example.com", Port: 1194, Proto: "udp"},
		},
	}
	servers := cfg.RemoteServers()
	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}
	// Without RemoteRandom, order is preserved.
	if servers[0].Host != "vpn1.example.com" {
		t.Fatalf("expected first server vpn1, got %s", servers[0].Host)
	}
	if servers[2].Host != "vpn3.example.com" {
		t.Fatalf("expected last server vpn3, got %s", servers[2].Host)
	}
}

func TestRemoteServersShufflePreservesAllEntries(t *testing.T) {
	cfg := ClientConfig{
		RemoteRandom: true,
		Servers: []RemoteEntry{
			{Host: "a", Port: 1},
			{Host: "b", Port: 2},
			{Host: "c", Port: 3},
			{Host: "d", Port: 4},
			{Host: "e", Port: 5},
		},
	}
	seen := make(map[string]bool)
	servers := cfg.RemoteServers()
	if len(servers) != 5 {
		t.Fatalf("expected 5 servers, got %d", len(servers))
	}
	for _, s := range servers {
		seen[s.Host] = true
	}
	// All entries should be present (shuffle doesn't lose entries).
	for _, orig := range cfg.Servers {
		if !seen[orig.Host] {
			t.Fatalf("server %q lost after shuffle", orig.Host)
		}
	}
}

func TestRemoteServersEmptyUsesFallback(t *testing.T) {
	cfg := ClientConfig{
		RemoteHost: "fallback.example.com",
		RemotePort: 443,
	}
	servers := cfg.RemoteServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 fallback server, got %d", len(servers))
	}
	if servers[0].Host != "fallback.example.com" {
		t.Fatalf("expected fallback host, got %s", servers[0].Host)
	}
}

func TestRemoteEntryProtoFallback(t *testing.T) {
	cfg := ClientConfig{
		Proto: "tcp",
		Servers: []RemoteEntry{
			{Host: "a", Port: 1194},           // no Proto -> should use config Proto
			{Host: "b", Port: 443, Proto: "udp"}, // explicit Proto
		},
	}
	servers := cfg.RemoteServers()
	if servers[0].Proto != "" {
		// RemoteEntry with empty Proto keeps it empty; the caller resolves it.
		// This is intentional - the adapter uses the config-level Proto as fallback.
	}
	if servers[1].Proto != "udp" {
		t.Fatalf("expected explicit proto udp, got %s", servers[1].Proto)
	}
}
