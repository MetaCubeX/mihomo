package tunnel

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
)

type icmpTestProxy struct {
	C.Proxy
	name string
	next C.Proxy
}

func (p *icmpTestProxy) Name() string                     { return p.name }
func (p *icmpTestProxy) Type() C.AdapterType              { return C.Direct }
func (p *icmpTestProxy) Unwrap(*C.Metadata, bool) C.Proxy { return p.next }

func TestICMPRuleRouting(t *testing.T) {
	oldRules, oldProxies, oldMode, oldStatus := rules, proxies, mode, status.Load()
	t.Cleanup(func() { rules, proxies, mode = oldRules, oldProxies, oldMode; status.Store(oldStatus) })
	online := &icmpTestProxy{name: "tailscale"}
	direct := &icmpTestProxy{name: "DIRECT"}
	group := &icmpTestProxy{name: "group", next: online}
	proxies = map[string]C.Proxy{"tailscale": online, "DIRECT": direct, "group": group, "GLOBAL": group}
	route, err := RC.NewIPCIDR("100.64.0.0/10", "group", RC.WithIPCIDRNoResolve(true))
	if err != nil {
		t.Fatal(err)
	}
	rules, mode = []C.Rule{route}, Rule
	OnRunning()
	metadata := func(ip string) *C.Metadata {
		return &C.Metadata{Type: C.TUN, SrcIP: netip.MustParseAddr("192.168.123.50"), DstIP: netip.MustParseAddr(ip)}
	}
	for _, tc := range []struct {
		ip   string
		want C.Proxy
	}{{"100.106.164.73", online}, {"8.8.8.8", direct}} {
		m := metadata(tc.ip)
		got, err := Tunnel.ResolveICMP(m)
		if err != nil || got != tc.want || m.NetWork != C.ICMP {
			t.Fatalf("%s: got %v, err %v", tc.ip, got, err)
		}
	}
	// ICMP must not accidentally match TCP/UDP NETWORK rules.
	tcpRule, _ := RC.NewNetworkType("TCP", "DIRECT")
	udpRule, _ := RC.NewNetworkType("UDP", "DIRECT")
	icmpRule, _ := RC.NewNetworkType("ICMP", "group")
	rules = []C.Rule{tcpRule, udpRule, icmpRule}
	if got, err := Tunnel.ResolveICMP(metadata("8.8.8.8")); err != nil || got != online {
		t.Fatalf("NETWORK,ICMP routing: %v %v", got, err)
	}
	mode = Direct
	if got, err := Tunnel.ResolveICMP(metadata("100.106.164.73")); err != nil || got != direct {
		t.Fatalf("direct mode: %v %v", got, err)
	}
	mode = Global
	if got, err := Tunnel.ResolveICMP(metadata("8.8.8.8")); err != nil || got != online {
		t.Fatalf("global mode: %v %v", got, err)
	}
	OnSuspend()
	if _, err := Tunnel.ResolveICMP(metadata("8.8.8.8")); err == nil {
		t.Fatal("suspended tunnel accepted ICMP")
	}
}
