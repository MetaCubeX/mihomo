//go:build !no_easytier

package outbound

import "testing"

func TestNewEasyTierRequiresConfigSource(t *testing.T) {
	_, err := NewEasyTier(EasyTierOption{Name: "et"})
	if err == nil {
		t.Fatal("expected missing config source")
	}
}

func TestNewEasyTierRejectsMixedSources(t *testing.T) {
	_, err := NewEasyTier(EasyTierOption{
		Name:        "et",
		NetworkName: "example",
		Config:      "hostname = \"x\"",
	})
	if err == nil {
		t.Fatal("expected xor error")
	}
}

func TestNewEasyTierStructuredNeedsPeers(t *testing.T) {
	_, err := NewEasyTier(EasyTierOption{
		Name:        "et",
		NetworkName: "example",
	})
	if err == nil {
		t.Fatal("expected missing peers")
	}
}

func TestNewEasyTierReadsZoneFromRawConfig(t *testing.T) {
	outbound, err := NewEasyTier(EasyTierOption{
		Name: "et-raw-zone",
		Config: `[network_identity]
network_name = "example"
network_secret = "secret"
[[peer]]
uri = "tcp://192.0.2.10:11010"
[flags]
tld_dns_zone = "overlay.example."
`,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbound.Close() })
	if outbound.zone != "overlay.example" {
		t.Fatalf("zone=%q", outbound.zone)
	}
}

func TestNewEasyTierStructuredZone(t *testing.T) {
	outbound, err := NewEasyTier(EasyTierOption{
		Name:          "et-structured-zone",
		NetworkName:   "example",
		NetworkSecret: "secret",
		Peers:         []string{"tcp://192.0.2.10:11010"},
		TLDDNSZone:    "custom.net.",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbound.Close() })
	if outbound.zone != "custom.net" {
		t.Fatalf("zone=%q", outbound.zone)
	}
}
