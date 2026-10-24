package tunnel

import (
	"context"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/neighbor"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/rules/wrapper"
)

func TestSourceMACLookupOnceAndOriginalSource(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.10")
	for _, found := range []bool{false, true} {
		meta := &C.Metadata{SrcIP: src, DstIP: netip.MustParseAddr("198.51.100.1")}
		calls := 0
		lookup := sourceMACLookup(meta, func(index int, ip netip.Addr) (neighbor.MAC, bool) {
			calls++
			if ip != src || index != 0 {
				t.Error("looked up swapped destination", ip)
			}
			return neighbor.MAC{2, 0, 0, 0, 0, 1}, found
		})
		meta.SwapSrcDst()
		lookup()
		meta.SwapSrcDst()
		lookup()
		if calls != 1 {
			t.Fatal("lookup repeated", calls)
		}
		if (meta.SrcMAC != "") != found {
			t.Fatal("incorrect MAC result", meta.SrcMAC)
		}
	}
	lookup := sourceMACLookup(&C.Metadata{Type: C.INNER, SrcIP: src}, func(int, netip.Addr) (neighbor.MAC, bool) {
		t.Error("internal connection queried neighbor table")
		return neighbor.MAC{}, false
	})
	lookup()
}

func parseMACRule(t *testing.T, kind, payload string) C.Rule {
	t.Helper()
	r, err := R.ParseRule(kind, payload, "DIRECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestSourceMACDemand(t *testing.T) {
	if !neighbor.Supported {
		t.Skip("no source MAC backend")
	}
	direct := parseMACRule(t, "SRC-MAC", "02:00:00:00:00:01")
	logic := parseMACRule(t, "AND", "((NETWORK,TCP),(SRC-MAC,02:00:00:00:00:01))")
	provider := RP.NewInlineProvider("devices", P.Classical, []string{"SRC-MAC,02:00:00:00:00:01"}, R.ParseRule)
	providers := map[string]P.RuleProvider{"devices": provider}
	rs := parseMACRule(t, "RULE-SET", "devices")
	wrapped := wrapper.NewRuleWrapper(rs)
	wrapped.SetDisabled(true)
	for _, tc := range []struct {
		name string
		rs   []C.Rule
		subs map[string][]C.Rule
		want bool
	}{
		{name: "unused provider", want: false},
		{name: "direct", rs: []C.Rule{direct}, want: true},
		{name: "logic", rs: []C.Rule{logic}, want: true},
		{name: "classical", rs: []C.Rule{rs}, want: true},
		{name: "disabled provider reference", rs: []C.Rule{wrapped}, want: false},
		{name: "inbound subrule", subs: map[string][]C.Rule{"devices": {direct}}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsSourceMAC(tc.rs, tc.subs, providers); got != tc.want {
				t.Fatal("demand", got)
			}
		})
	}
	wrapped.SetDisabled(false)
	if !needsSourceMAC([]C.Rule{wrapped}, nil, providers) {
		t.Fatal("re-enabled reference ignored")
	}
	providers["devices"] = RP.NewInlineProvider("devices", P.Classical, []string{"DOMAIN,example.com"}, R.ParseRule)
	if needsSourceMAC([]C.Rule{rs}, nil, providers) {
		t.Fatal("removed provider demand retained")
	}
}

type recordingMACResolver struct {
	enabled       bool
	starts, stops int
}

func (r *recordingMACResolver) SetEnabled(v bool) {
	if v && !r.enabled {
		r.starts++
	}
	if !v && r.enabled {
		r.stops++
	}
	r.enabled = v
}
func (r *recordingMACResolver) Lookup(int, netip.Addr) (neighbor.MAC, bool) {
	return neighbor.MAC{}, false
}
func TestSourceMACConfigurationLifecycle(t *testing.T) {
	if !neighbor.Supported {
		t.Skip("no source MAC backend")
	}
	original := sourceMACResolver
	oldRules, oldSubs, oldProviders, oldClosed := rules, subRules, ruleProviders, sourceMACClosed
	fake := &recordingMACResolver{}
	sourceMACResolver = fake
	defer func() {
		sourceMACResolver = original
		rules, subRules, ruleProviders, sourceMACClosed = oldRules, oldSubs, oldProviders, oldClosed
	}()
	UpdateRules(nil, nil, nil)
	if fake.starts != 0 {
		t.Fatal("empty config started backend")
	}
	r := wrapper.NewRuleWrapper(parseMACRule(t, "SRC-MAC", "02:00:00:00:00:01"))
	UpdateRules([]C.Rule{r}, nil, nil)
	RefreshSourceMAC()
	if fake.starts != 1 {
		t.Fatal("repeated refresh restarted backend")
	}
	r.SetDisabled(true)
	RefreshSourceMAC()
	if fake.enabled {
		t.Fatal("last disabled rule retained backend")
	}
	r.SetDisabled(false)
	RefreshSourceMAC()
	ShutdownSourceMAC()
	RefreshSourceMAC()
	if fake.enabled {
		t.Fatal("late callback restarted backend after shutdown")
	}
	UpdateRules([]C.Rule{r}, nil, nil)
	if !fake.enabled {
		t.Fatal("new configuration did not restart backend")
	}
	UpdateRules(nil, nil, nil)
	RefreshSourceMAC()
	if fake.enabled {
		t.Fatal("late callback used old configuration")
	}
}

func (r *recordingMACResolver) Configure(neighbor.Options) {}
func (r *recordingMACResolver) Options() neighbor.Options  { return neighbor.DefaultOptions() }
func (r *recordingMACResolver) Resolve(context.Context, int, netip.Addr) (neighbor.MAC, bool) {
	return neighbor.MAC{}, false
}
