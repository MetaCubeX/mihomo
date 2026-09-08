package easytier

import (
	"net/netip"
	"testing"
)

func TestLookupOverlayHost(t *testing.T) {
	ip := netip.MustParseAddr("10.144.0.2")
	nodes := []Node{{Hostname: "peer", IPv4: ip}}
	got, ok := LookupOverlayHost("peer.et.net.", "et.net.", nodes)
	if !ok || got != ip {
		t.Fatalf("got %v %v", got, ok)
	}
	if _, ok := LookupOverlayHost("missing", "et.net.", nodes); ok {
		t.Fatal("expected miss")
	}
}

func TestParsePTRAndNodeIPv4(t *testing.T) {
	ip, ok := ParsePTRIPv4("2.0.144.10.in-addr.arpa.")
	if !ok || ip.String() != "10.144.0.2" {
		t.Fatalf("ptr: %v %v", ip, ok)
	}
	got, err := ParseNodeIPv4("10.144.0.1/24")
	if err != nil || got.String() != "10.144.0.1" {
		t.Fatalf("cidr: %v %v", got, err)
	}
}

func TestIsMagicDNS(t *testing.T) {
	if IsMagicDNS("peer", "et.net.") {
		t.Fatal("single-label name should not be magic dns")
	}
	if !IsMagicDNS("peer.et.net", "") {
		t.Fatal("expected magic dns")
	}
	if IsMagicDNS("example.com", "et.net.") {
		t.Fatal("public name should not be magic dns")
	}
}
