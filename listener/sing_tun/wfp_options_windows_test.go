//go:build windows && (amd64 || 386)

package sing_tun

import (
	"math"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
)

func TestWFPOptions(t *testing.T) {
	l := &Listener{options: LC.Tun{Stack: C.TunMips, ExcludeSrcPortRange: []string{"1000:2000"}, ExcludeDstPortRange: []string{"65535:65535"}}, handler: &ListenerHandler{}}
	options, err := l.wfpOptions()
	if err != nil {
		t.Fatal(err)
	}
	if options.MTU != 1500 || options.UDPTimeout != sing.UDPTimeout || options.HijackDNS != nil || options.ExcludeDstPortRange[0].End != 65535 {
		t.Fatalf("incorrect options: %+v", options)
	}
	l.handler.DnsAddrPorts = []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:53")}
	options, err = l.wfpOptions()
	if err != nil || len(options.HijackDNS) != 1 || options.HijackDNS[0] != l.handler.DnsAddrPorts[0] {
		t.Fatal("IPv6 DNS exception lost", err)
	}
	for _, value := range []string{"-1:53", "53:1", "1:65536", "65536:65537", "1", ":53"} {
		l.options.ExcludeSrcPortRange = []string{value}
		if _, err := l.wfpOptions(); err == nil {
			t.Fatalf("invalid port interval accepted: %s", value)
		}
	}
	l.options.ExcludeSrcPortRange = nil
	for _, timeout := range []int64{-1, math.MaxInt64} {
		l.options.UDPTimeout = timeout
		if _, err := l.wfpOptions(); err == nil {
			t.Fatalf("invalid timeout accepted: %d", timeout)
		}
	}
	l.options.UDPTimeout = 0
	l.options.IncludeUID = []uint32{1000}
	if _, err := l.wfpOptions(); err == nil {
		t.Fatal("unsupported process policy ignored")
	}
}
