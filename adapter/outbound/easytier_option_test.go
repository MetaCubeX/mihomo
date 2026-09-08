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
