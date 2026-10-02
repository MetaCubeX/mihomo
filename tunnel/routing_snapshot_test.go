package tunnel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/neighbor"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
)

func TestRoutingWaitDoesNotHoldConfigLockOrRestart(t *testing.T) {
	if !neighbor.Supported {
		t.Skip("no MAC backend")
	}
	oldRules, oldSubs, oldProxies, oldProviders, oldResolver, oldClosed := rules, subRules, proxies, ruleProviders, sourceMACResolver, sourceMACClosed
	oldProxyProviders := providers
	defer func() {
		rules, subRules, proxies, ruleProviders, sourceMACResolver, sourceMACClosed = oldRules, oldSubs, oldProxies, oldProviders, oldResolver, oldClosed
		providers = oldProxyProviders
	}()
	sourceMACResolver = &recordingMACResolver{}
	direct := &snapshotTestProxy{name: "direct"}
	proxies = map[string]C.Proxy{"DIRECT": direct}
	macRule := parseMACRule(t, "SRC-MAC", "02:00:00:00:00:01")
	UpdateRules([]C.Rule{macRule}, nil, nil)
	waiting, release := make(chan struct{}), make(chan struct{})
	result := make(chan C.Proxy, 1)
	meta := &C.Metadata{SrcIP: netip.MustParseAddr("192.0.2.2")}
	calls := 0
	go func() {
		p, _, err := match(meta, C.RuleMatchHelper{FindSourceMAC: func() { calls++; close(waiting); <-release; meta.SrcMAC = "02:00:00:00:00:01" }})
		if err != nil {
			t.Error(err)
		}
		result <- p
	}()
	<-waiting
	updated := make(chan struct{})
	go func() {
		UpdateRules(nil, nil, nil)
		UpdateProxies(map[string]C.Proxy{"DIRECT": &snapshotTestProxy{name: "changed"}}, nil)
		close(updated)
	}()
	select {
	case <-updated:
	case <-time.After(time.Second):
		close(release)
		<-result
		<-updated
		t.Fatal("MAC wait blocked config update")
	}
	close(release)
	if p := <-result; p != direct || calls != 1 {
		t.Fatal("configuration was mixed or expression restarted", p, calls)
	}
}

func TestRoutingRuleSetSourceIdentityAndShortCircuit(t *testing.T) {
	if !neighbor.Supported {
		t.Skip("no MAC backend")
	}
	direct := &snapshotTestProxy{name: "direct"}
	provider := RP.NewInlineProvider("devices", P.Classical, []string{"SRC-MAC,02:00:00:00:00:01"}, R.ParseRule)
	rs, err := R.ParseRule("RULE-SET", "devices", "DIRECT", []string{"src"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := routingSnapshot{rules: []C.Rule{rs}, proxies: map[string]C.Proxy{"DIRECT": direct}, providers: map[string]P.RuleProvider{"devices": provider}}
	original := netip.MustParseAddr("192.0.2.2")
	meta := &C.Metadata{SrcIP: original, DstIP: netip.MustParseAddr("198.51.100.1")}
	count := 0
	helper := C.RuleMatchHelper{FindSourceMAC: sourceMACLookup(meta, func(_ int, ip netip.Addr) (neighbor.MAC, bool) {
		count++
		if ip != original {
			t.Error("queried swapped destination")
		}
		return neighbor.MAC{2, 0, 0, 0, 0, 1}, true
	})}
	if p, rule, err := state.match(meta, helper); err != nil || p != direct || rule != rs || count != 1 || meta.SrcIP != original {
		t.Fatal("source rule-set match failed", p, rule, err, count)
	}
	first, err := R.ParseRule("MATCH", "", "DIRECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state.rules = []C.Rule{first, rs}
	if _, _, err := state.match(meta, C.RuleMatchHelper{FindSourceMAC: func() { t.Error("earlier match did not skip recovery") }}); err != nil {
		t.Fatal(err)
	}
}

type changingStrategyProvider struct {
	P.RuleProvider
	strategy C.RuleSetMatcher
}

func (p *changingStrategyProvider) Strategy() any { return p.strategy }
func TestRoutingProviderStrategyPinned(t *testing.T) {
	first := RP.NewInlineProvider("devices", P.Classical, []string{"DOMAIN,one.example"}, R.ParseRule)
	second := RP.NewInlineProvider("devices", P.Classical, []string{"DOMAIN,two.example"}, R.ParseRule)
	p := &changingStrategyProvider{RuleProvider: first, strategy: first.Strategy().(C.RuleSetMatcher)}
	state := routingSnapshot{providers: map[string]P.RuleProvider{"devices": p}}
	helper := state.helpers(&C.Metadata{}, C.RuleMatchHelper{})
	pinned := helper.RuleSetLookup("devices")
	p.strategy = second.Strategy().(C.RuleSetMatcher)
	if helper.RuleSetLookup("devices") != pinned {
		t.Fatal("provider update changed current evaluation")
	}
	if state.helpers(&C.Metadata{}, C.RuleMatchHelper{}).RuleSetLookup("devices") == pinned {
		t.Fatal("new evaluation retained stale provider")
	}
}

type snapshotTestProxy struct {
	C.Proxy
	name string
}

func (p *snapshotTestProxy) Name() string                     { return p.name }
func (p *snapshotTestProxy) Type() C.AdapterType              { return C.Direct }
func (p *snapshotTestProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }
func (p *snapshotTestProxy) SupportUDP() bool                 { return true }
