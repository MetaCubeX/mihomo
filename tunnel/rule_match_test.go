package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
)

type ruleMatchTestResolver struct {
	resolver.Resolver
	lookup func(context.Context, string) ([]netip.Addr, error)
}

func (r ruleMatchTestResolver) Invalid() bool { return true }
func (r ruleMatchTestResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, host)
}

// Any accidental business dial or process-aware adapter operation panics through
// the unused embedded interface rather than hiding a diagnostic side effect.
type ruleMatchTestProxy struct {
	C.Proxy
	name string
}

func (p ruleMatchTestProxy) Name() string                     { return p.name }
func (p ruleMatchTestProxy) Type() C.AdapterType              { return C.Direct }
func (p ruleMatchTestProxy) SupportUDP() bool                 { return true }
func (p ruleMatchTestProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }
func (p ruleMatchTestProxy) Adapter() C.ProxyAdapter          { return p }

func withRuleMatchTestResolver(t *testing.T, lookup func(context.Context, string) ([]netip.Addr, error)) {
	t.Helper()
	oldResolver, oldHosts, oldIPv6 := resolver.DefaultResolver, resolver.DefaultHosts, resolver.DisableIPv6
	resolver.DefaultResolver = ruleMatchTestResolver{lookup: lookup}
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	resolver.DisableIPv6 = true
	t.Cleanup(func() {
		resolver.DefaultResolver, resolver.DefaultHosts, resolver.DisableIPv6 = oldResolver, oldHosts, oldIPv6
	})
}

func TestMatchRulesDNSSnapshotAllowsConfigWriterAndReentry(t *testing.T) {
	configMux.RLock()
	oldRules, oldSubRules, oldProviders, oldProxies := rules, subRules, ruleProviders, proxies
	configMux.RUnlock()
	t.Cleanup(func() {
		configMux.Lock()
		rules, subRules, ruleProviders, proxies = oldRules, oldSubRules, oldProviders, oldProxies
		configMux.Unlock()
	})
	parse := func(tp, payload, policy string) C.Rule {
		rule, err := R.ParseRule(tp, payload, policy, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return rule
	}
	oldProvider := RP.NewInlineProvider("snapshot", P.IPCIDR, []string{"192.0.2.0/24"}, R.ParseRule)
	newProvider := RP.NewInlineProvider("snapshot", P.IPCIDR, []string{"203.0.113.0/24"}, R.ParseRule)
	newRules := []C.Rule{parse("MATCH", "", "NEW")}
	UpdateRules([]C.Rule{
		parse("IP-CIDR", "198.51.100.0/24", "OLD"),
		parse("RULE-SET", "snapshot", "OLD"),
	}, nil, map[string]P.RuleProvider{"snapshot": oldProvider})
	UpdateProxies(map[string]C.Proxy{"OLD": ruleMatchTestProxy{name: "OLD"}}, providers)
	calls := 0
	withRuleMatchTestResolver(t, func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls++
		// A DNS request may route through the live matcher while a config
		// writer is waiting. Prove no outer reader lock can block that writer.
		if !configMux.TryLock() {
			return nil, errors.New("diagnostic held configMux while resolving DNS")
		}
		rules = newRules
		ruleProviders = map[string]P.RuleProvider{"snapshot": newProvider}
		proxies = map[string]C.Proxy{"NEW": ruleMatchTestProxy{name: "NEW"}}
		configMux.Unlock()
		proxy, _, err := match(&C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.9")}, C.RuleMatchHelper{})
		if err != nil || proxy == nil || proxy.Name() != "NEW" {
			return nil, errors.New("recursive live match did not see updated configuration")
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, nil
	})
	result := MatchRules(context.Background(), C.Metadata{NetWork: C.TCP, Host: "snapshot.test"}, nil, true)
	if !result.Complete || result.Policy != "OLD" || result.IP != "192.0.2.9" || result.Rule == nil || result.Rule.Index != 1 || !result.DNS.Attempted || result.DNS.Error != "" || calls != 1 {
		t.Fatalf("diagnostic lost its rules/proxies/provider snapshot during DNS: %+v, calls=%d", result, calls)
	}
}

func TestResolveRuleIPSharedSemantics(t *testing.T) {
	for _, tc := range []struct {
		name      string
		metadata  C.Metadata
		lookupErr error
		wantCalls int
		wantIP    string
	}{
		{name: "one successful lookup", metadata: C.Metadata{Host: "lazy.test"}, wantCalls: 1, wantIP: "192.0.2.9"},
		{name: "one failed lookup", metadata: C.Metadata{Host: "lazy.test"}, lookupErr: errors.New("upstream failed"), wantCalls: 1},
		{name: "no host", metadata: C.Metadata{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			withRuleMatchTestResolver(t, func(ctx context.Context, host string) ([]netip.Addr, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > resolver.DefaultDNSTimeout {
					t.Errorf("shared lazy resolver did not impose default DNS timeout")
				}
				return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, tc.lookupErr
			})
			resolved := false
			attempted, err := resolveRuleIP(context.Background(), &tc.metadata, &resolved)
			if attempted != (tc.wantCalls != 0) || !errors.Is(err, tc.lookupErr) {
				t.Fatalf("attempted=%v err=%v", attempted, err)
			}
			if attempted, err := resolveRuleIP(context.Background(), &tc.metadata, &resolved); attempted || err != nil {
				t.Fatalf("second invocation retried: attempted=%v err=%v", attempted, err)
			}
			if calls != tc.wantCalls || (tc.metadata.DstIP.IsValid() && tc.metadata.DstIP.String() != tc.wantIP) || (!tc.metadata.DstIP.IsValid() && tc.wantIP != "") {
				t.Fatalf("calls=%d metadata=%+v", calls, tc.metadata)
			}
		})
	}
}

func TestResolveRuleIPRequestContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	withRuleMatchTestResolver(t, func(ctx context.Context, host string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, nil
	})
	metadata, resolved := C.Metadata{Host: "cancel.test"}, false
	attempted, err := resolveRuleIP(ctx, &metadata, &resolved)
	if !attempted || !errors.Is(err, context.Canceled) || metadata.DstIP.IsValid() {
		t.Fatalf("cancelled response accepted: attempted=%v err=%v ip=%s", attempted, err, metadata.DstIP)
	}
	// A request cancelled before matching must not start an upstream exchange.
	withRuleMatchTestResolver(t, func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("pre-cancelled request reached resolver")
		return nil, nil
	})
	resolved = false
	attempted, err = resolveRuleIP(ctx, &metadata, &resolved)
	if !attempted || !errors.Is(err, context.Canceled) || metadata.DstIP.IsValid() {
		t.Fatalf("pre-cancelled result: attempted=%v err=%v", attempted, err)
	}
}

func TestMatchRulesDNSDeadline(t *testing.T) {
	oldRules, oldSubRules, oldProviders := rules, subRules, ruleProviders
	t.Cleanup(func() { UpdateRules(oldRules, oldSubRules, oldProviders) })
	rule, err := R.ParseRule("IP-CIDR", "192.0.2.0/24", "DIRECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	UpdateRules([]C.Rule{rule}, nil, nil)
	var expectedDeadline time.Time
	withRuleMatchTestResolver(t, func(ctx context.Context, host string) ([]netip.Addr, error) {
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(expectedDeadline) {
			t.Error("resolver did not inherit the earlier request deadline")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	expectedDeadline, _ = ctx.Deadline()
	result := MatchRules(ctx, C.Metadata{Host: "deadline.test", NetWork: C.TCP}, nil, true)
	if result.Complete || result.Policy != "" || result.IP != "" || !result.DNS.Attempted || result.DNS.Error != context.DeadlineExceeded.Error() || len(result.Missing) != 1 || result.Missing[0] != "ip" {
		t.Fatalf("deadline must be an explicit incomplete result: %+v", result)
	}
}

func TestResolveRuleIPHostsAndSuppliedIP(t *testing.T) {
	withRuleMatchTestResolver(t, func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("configured hosts should not reach DNS upstream")
		return nil, nil
	})
	if err := resolver.DefaultHosts.Insert("hosts.test", resolver.HostValue{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.9")}}); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []netip.Addr{{}, netip.MustParseAddr("198.51.100.7")} {
		metadata, resolved := C.Metadata{Host: "hosts.test", DstIP: ip}, false
		attempted, err := resolveRuleIP(context.Background(), &metadata, &resolved)
		wantIP := ip
		if !wantIP.IsValid() {
			wantIP = netip.MustParseAddr("192.0.2.9")
		}
		if err != nil || attempted == ip.IsValid() || metadata.DstIP != wantIP {
			t.Fatalf("hosts lookup overwrote input or skipped resolution: attempted=%v err=%v metadata=%+v", attempted, err, metadata)
		}
	}
}
