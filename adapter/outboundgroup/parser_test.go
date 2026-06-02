package outboundgroup

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// baseProxyMap builds a minimal proxyMap covering the built-in outbounds
// plus any extra names the test passes in. Each "extra" is a Direct proxy
// under the requested name so the type happens to be C.Direct — tests that
// need a specific type should build their own proxyMap.
func baseProxyMap(extra ...string) map[string]C.Proxy {
	m := map[string]C.Proxy{
		"DIRECT":      adapter.NewProxy(outbound.NewDirect()),
		"REJECT":      adapter.NewProxy(outbound.NewReject()),
		"REJECT-DROP": adapter.NewProxy(outbound.NewRejectDrop()),
		"PASS":        adapter.NewProxy(outbound.NewPass()),
	}
	for _, name := range extra {
		// NewDirect produces a proxy named "DIRECT"; wrap a proxy with the
		// desired name by going through the DIRECT template. For validation
		// tests we only need proxyMap lookup to succeed and the type string
		// to be stable — the actual dial behavior is irrelevant.
		m[name] = adapter.NewProxy(outbound.NewDirect())
	}
	return m
}

// --- filterStaticProxies --------------------------------------------------

func TestFilterStaticProxies_NoExclude(t *testing.T) {
	names := []string{"a", "b", "c"}
	got := filterStaticProxies(names, "", "", baseProxyMap("a", "b", "c"))
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("no-exclude: want [a b c], got %v", got)
	}
	// Must be a defensive copy.
	names[0] = "mutated"
	if got[0] != "a" {
		t.Errorf("filterStaticProxies did not copy the input slice; got[0]=%q", got[0])
	}
}

func TestFilterStaticProxies_EmptyInput(t *testing.T) {
	if got := filterStaticProxies(nil, "", "", nil); got != nil {
		t.Errorf("nil in → nil out, got %v", got)
	}
	if got := filterStaticProxies([]string{}, "^x$", "", nil); got != nil {
		t.Errorf("empty in → nil out, got %v", got)
	}
}

func TestFilterStaticProxies_ExcludeFilter(t *testing.T) {
	names := []string{"hk", "us", "DIRECT"}
	got := filterStaticProxies(names, "^DIRECT$", "", baseProxyMap("hk", "us"))
	if len(got) != 2 || got[0] != "hk" || got[1] != "us" {
		t.Errorf("exclude-filter ^DIRECT$: want [hk us], got %v", got)
	}
}

func TestFilterStaticProxies_ExcludeFilterMultiPattern(t *testing.T) {
	names := []string{"hk", "us", "tokyo", "osaka"}
	// Backtick-separated regex list: same semantics as GroupBase.
	got := filterStaticProxies(names, "^hk$`^osaka$", "", baseProxyMap("hk", "us", "tokyo", "osaka"))
	if len(got) != 2 || got[0] != "us" || got[1] != "tokyo" {
		t.Errorf("exclude-filter backtick list: want [us tokyo], got %v", got)
	}
}

func TestFilterStaticProxies_ExcludeType(t *testing.T) {
	// Build a proxyMap where "DIRECT" and "REJECT" have distinct types.
	pm := baseProxyMap()
	got := filterStaticProxies([]string{"DIRECT", "REJECT"}, "", "Direct", pm)
	if len(got) != 1 || got[0] != "REJECT" {
		t.Errorf("exclude-type Direct: want [REJECT], got %v", got)
	}
}

func TestFilterStaticProxies_ExcludeTypeCaseInsensitive(t *testing.T) {
	pm := baseProxyMap()
	got := filterStaticProxies([]string{"DIRECT"}, "", "direct", pm)
	if len(got) != 0 {
		t.Errorf("exclude-type direct (lowercase) should still match Direct type; got %v", got)
	}
}

func TestFilterStaticProxies_ExcludeTypeMultiPipe(t *testing.T) {
	pm := baseProxyMap()
	got := filterStaticProxies([]string{"DIRECT", "REJECT", "PASS"}, "", "Direct|Reject", pm)
	// PASS is a "Pass" type, not Direct/Reject → kept.
	if len(got) != 1 || got[0] != "PASS" {
		t.Errorf("exclude-type Direct|Reject: want [PASS], got %v", got)
	}
}

func TestFilterStaticProxies_NameMissingFromProxyMap(t *testing.T) {
	// proxy name that proxyMap doesn't resolve: ExcludeType cannot match, so
	// it should pass through (downstream getProxies will flag the bug).
	got := filterStaticProxies([]string{"ghost"}, "", "Direct", baseProxyMap())
	if len(got) != 1 || got[0] != "ghost" {
		t.Errorf("unresolved name should be preserved; got %v", got)
	}
}

// --- ParseProxyGroup ------------------------------------------------------

// parseGroup is a thin wrapper so tests can call ParseProxyGroup with a
// baseline proxyMap and empty provider/AllProviders/AllNetworks arguments.
func parseGroup(config map[string]any, opts ...func(*parseGroupArgs)) (C.ProxyAdapter, error) {
	args := &parseGroupArgs{
		proxyMap:      baseProxyMap("hk", "us"),
		providersMap:  map[string]P.ProxyProvider{},
		allProxies:    []string{"hk", "us"},
		allProviders:  nil,
		allNetworks:   nil,
		allProxyNames: []string{"DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "hk", "us"},
	}
	for _, opt := range opts {
		opt(args)
	}
	return ParseProxyGroup(config, args.proxyMap, args.providersMap, args.allProxies, args.allProviders, args.allNetworks, args.allProxyNames)
}

type parseGroupArgs struct {
	proxyMap      map[string]C.Proxy
	providersMap  map[string]P.ProxyProvider
	allProxies    []string
	allProviders  []string
	allNetworks   []string
	allProxyNames []string
}

func withNetworks(names ...string) func(*parseGroupArgs) {
	return func(a *parseGroupArgs) { a.allNetworks = names }
}

// withAllProxyNames overrides the global proxy-name set for tests that want
// to exercise the "globally known but not reachable from this group" branch.
func withAllProxyNames(names ...string) func(*parseGroupArgs) {
	return func(a *parseGroupArgs) { a.allProxyNames = names }
}

// Non-select group with network-policy is a parse-time error (architecture
// §5.8.1). Exercising all three non-select group types would be overkill;
// one representative (url-test) is sufficient — the check is on
// groupOption.Type alone.
func TestParseProxyGroup_NetworkPolicyOnNonSelect_Rejected(t *testing.T) {
	cfg := map[string]any{
		"name":    "sel",
		"type":    "url-test",
		"url":     "http://example.com",
		"proxies": []any{"hk", "us"},
		"network-policy": map[string]any{
			"office": "hk",
		},
	}
	_, err := parseGroup(cfg, withNetworks("office"))
	if err == nil || !strings.Contains(err.Error(), "only supported on select groups") {
		t.Errorf("want select-only error, got %v", err)
	}
}

// exclude-filter applied to a static proxy makes it unreachable at runtime;
// the parse-time validator must catch this before the user sees a
// missing_target at the first PUT. The target DIRECT is a built-in so it
// lives in the global proxy set — that puts the error on the "globally
// known but not reachable from this group" branch (§5.8.1 row 4.a),
// distinct from the "unknown everywhere" branch.
func TestParseProxyGroup_ExcludeFilter_TargetFailsParseTime(t *testing.T) {
	cfg := map[string]any{
		"name":           "sel",
		"type":           "select",
		"proxies":        []any{"DIRECT"},
		"exclude-filter": "^DIRECT$",
		"network-policy": map[string]any{
			"office": "DIRECT",
		},
	}
	_, err := parseGroup(cfg, withNetworks("office"))
	if err == nil || !strings.Contains(err.Error(), "not reachable by this group") {
		t.Errorf("want parse-time unreachable error after exclude-filter; got %v", err)
	}
}

// Happy path: exclude-filter that doesn't hit the target leaves it reachable.
func TestParseProxyGroup_ExcludeFilter_DoesNotHitTarget(t *testing.T) {
	cfg := map[string]any{
		"name":           "sel",
		"type":           "select",
		"proxies":        []any{"hk", "us"},
		"exclude-filter": "^jp$", // doesn't match hk or us
		"network-policy": map[string]any{
			"office": "hk",
		},
	}
	if _, err := parseGroup(cfg, withNetworks("office")); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Regression: globalProxyNames must be a stable caller-precomputed set,
// not derived from proxyMap during group iteration. A target that names
// another group which has not yet been parsed should still be recognized
// as "globally known but not reachable from this group" (§5.8.1 case 2),
// never as "not found anywhere" (case 4). This test simulates the
// situation by supplying allProxyNames that contains a group name which
// proxyMap does NOT yet know about.
func TestParseProxyGroup_GlobalButUnreachable_ReferencesLaterGroup(t *testing.T) {
	cfg := map[string]any{
		"name":    "sel",
		"type":    "select",
		"proxies": []any{"hk"},
		"network-policy": map[string]any{
			"office": "some-later-group",
		},
	}
	// proxyMap deliberately does NOT contain some-later-group, but the
	// caller-supplied allProxyNames does — the validator must still fail
	// fast with "not reachable by this group".
	_, err := parseGroup(cfg,
		withNetworks("office"),
		withAllProxyNames("DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "hk", "us", "some-later-group"),
	)
	if err == nil || !strings.Contains(err.Error(), "not reachable by this group") {
		t.Errorf("want unreachable-from-this-group error for later-group target; got %v", err)
	}
}

// Happy path for the common case without network-policy — make sure the
// new SetNetworkPolicy call path doesn't break existing select groups.
func TestParseProxyGroup_SelectWithoutNetworkPolicy(t *testing.T) {
	cfg := map[string]any{
		"name":    "sel",
		"type":    "select",
		"proxies": []any{"hk", "us"},
	}
	adapter, err := parseGroup(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sel, ok := adapter.(*Selector)
	if !ok {
		t.Fatalf("expected *Selector, got %T", adapter)
	}
	if !sel.NetworkPolicy().IsEmpty() {
		t.Errorf("selector without network-policy field should report empty policy, got %+v", sel.NetworkPolicy())
	}
}
