//go:build windows && (amd64 || 386)

package sing_tun

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

func TestWFPDNSClient(t *testing.T) {
	mode := os.Getenv("MIHOMO_WFP_CLIENT")
	if mode == "" {
		t.Skip("DNS integration subprocess")
	}
	destination := "198.18.0.1:53"
	if strings.HasSuffix(mode, "6") {
		destination = "[2001:db8::1]:53"
	}
	query := new(D.Msg)
	query.SetQuestion("wfp.example.com.", D.TypeA)
	client := &D.Client{Net: mode, Timeout: 5 * time.Second}
	reply, _, err := client.Exchange(query, destination)
	if err != nil {
		t.Fatal(err)
	}
	for _, answer := range reply.Answer {
		if a, ok := answer.(*D.A); ok {
			ip, _ := netip.AddrFromSlice(a.A)
			if netip.MustParsePrefix("198.18.0.0/16").Contains(ip.Unmap()) {
				return
			}
		}
	}
	t.Fatalf("expected a fake-IP answer, got %v", reply.Answer)
}
