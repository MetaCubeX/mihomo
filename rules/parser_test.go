package rules

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseRuleGEOIPSlashLan(t *testing.T) {
	t.Parallel()

	rule, err := ParseRule("GEOIP", " LAN / lan ", "DIRECT", nil, nil)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if got, want := rule.Payload(), "lan"; got != want {
		t.Fatalf("unexpected payload: got %q, want %q", got, want)
	}

	matched, adapter := rule.Match(&C.Metadata{DstIP: netip.MustParseAddr("192.168.1.1")}, C.RuleMatchHelper{})
	if !matched {
		t.Fatalf("expected parsed slash geoip rule to match lan address")
	}
	if adapter != "DIRECT" {
		t.Fatalf("unexpected adapter: got %q, want %q", adapter, "DIRECT")
	}
}
