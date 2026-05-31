package resolver

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/trie"

	"github.com/miekg/dns"
)

// fakeResolver resolves a fixed host->IPs map and reports Invalid()==true so the
// resolver.Lookup* functions take the "use provided resolver" branch.
type fakeResolver struct {
	m map[string][]netip.Addr
}

func (f *fakeResolver) lookup(host string) ([]netip.Addr, error) {
	if ips, ok := f.m[host]; ok {
		return ips, nil
	}
	return nil, errors.New("fakeResolver: no such host: " + host)
}

func (f *fakeResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	return f.lookup(host)
}

func (f *fakeResolver) LookupIPv4(_ context.Context, host string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0)
	ips, err := f.lookup(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.Is4() {
			out = append(out, ip)
		}
	}
	return out, nil
}

func (f *fakeResolver) LookupIPv6(_ context.Context, host string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0)
	ips, err := f.lookup(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.Is6() {
			out = append(out, ip)
		}
	}
	return out, nil
}

func (f *fakeResolver) ResolveECH(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (f *fakeResolver) ExchangeContext(_ context.Context, _ *dns.Msg) (*dns.Msg, error) {
	return nil, nil
}
func (f *fakeResolver) Invalid() bool    { return true }
func (f *fakeResolver) ClearCache()      {}
func (f *fakeResolver) ResetConnection() {}

func insertHost(t *testing.T, tree *trie.DomainTrie[HostValue], domain string, value ...string) {
	t.Helper()
	hv, err := NewHostValue(value)
	if err != nil {
		t.Fatalf("NewHostValue(%v): %v", value, err)
	}
	if err := tree.Insert(domain, hv); err != nil {
		t.Fatalf("Insert(%s): %v", domain, err)
	}
}

func withHostsAndIPv6(t *testing.T, disableIPv6 bool, build func(tree *trie.DomainTrie[HostValue])) {
	t.Helper()
	origHosts := DefaultHosts
	origDisableIPv6 := DisableIPv6
	t.Cleanup(func() {
		DefaultHosts = origHosts
		DisableIPv6 = origDisableIPv6
	})
	tree := trie.New[HostValue]()
	build(tree)
	tree.Optimize()
	DefaultHosts = NewHosts(tree)
	DisableIPv6 = disableIPv6
}

// node domain a.com mapped to real domain b.com (b.com resolves to an IP).
// This is the user's scenario: a.com is a proxy node domain, b.com carries the
// real IP; dialing the node must resolve b.com, not a.com.
func TestLookupIPv4_DomainRedirect(t *testing.T) {
	withHostsAndIPv6(t, true, func(tree *trie.DomainTrie[HostValue]) {
		insertHost(t, tree, "a.com", "b.com")
	})
	fake := &fakeResolver{m: map[string][]netip.Addr{
		"b.com": {netip.MustParseAddr("1.1.1.1")},
		"a.com": {netip.MustParseAddr("2.2.2.2")},
	}}

	ips, err := LookupIPv4WithResolver(context.Background(), "a.com", fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("expected redirect a.com -> b.com (1.1.1.1), got %v", ips)
	}
}

func TestLookupIP_DomainRedirect(t *testing.T) {
	withHostsAndIPv6(t, true, func(tree *trie.DomainTrie[HostValue]) {
		insertHost(t, tree, "a.com", "b.com")
	})
	fake := &fakeResolver{m: map[string][]netip.Addr{
		"b.com": {netip.MustParseAddr("1.1.1.1")},
		"a.com": {netip.MustParseAddr("2.2.2.2")},
	}}

	ips, err := LookupIPWithResolver(context.Background(), "a.com", fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("expected redirect a.com -> b.com (1.1.1.1), got %v", ips)
	}
}

func TestLookupIPv6_DomainRedirect(t *testing.T) {
	withHostsAndIPv6(t, false, func(tree *trie.DomainTrie[HostValue]) {
		insertHost(t, tree, "a.com", "b.com")
	})
	fake := &fakeResolver{m: map[string][]netip.Addr{
		"b.com": {netip.MustParseAddr("2606:4700:4700::1111")},
		"a.com": {netip.MustParseAddr("2606:4700:4700::2222")},
	}}

	ips, err := LookupIPv6WithResolver(context.Background(), "a.com", fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("2606:4700:4700::1111") {
		t.Fatalf("expected redirect a.com -> b.com (2606:4700:4700::1111), got %v", ips)
	}
}

// regression: domain -> IP must keep working unchanged.
func TestLookupIPv4_DomainToIP(t *testing.T) {
	withHostsAndIPv6(t, true, func(tree *trie.DomainTrie[HostValue]) {
		insertHost(t, tree, "a.com", "111.111.111.111")
	})
	fake := &fakeResolver{m: map[string][]netip.Addr{}}

	ips, err := LookupIPv4WithResolver(context.Background(), "a.com", fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("111.111.111.111") {
		t.Fatalf("expected a.com -> 111.111.111.111, got %v", ips)
	}
}

// chained redirect a.com -> b.com -> IP (b.com is itself a hosts entry).
func TestLookupIPv4_ChainedRedirectToHostsIP(t *testing.T) {
	withHostsAndIPv6(t, true, func(tree *trie.DomainTrie[HostValue]) {
		insertHost(t, tree, "a.com", "b.com")
		insertHost(t, tree, "b.com", "3.3.3.3")
	})
	fake := &fakeResolver{m: map[string][]netip.Addr{}}

	ips, err := LookupIPv4WithResolver(context.Background(), "a.com", fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("3.3.3.3") {
		t.Fatalf("expected chained a.com -> b.com -> 3.3.3.3, got %v", ips)
	}
}

// exercises the re-entrant branch: LookupIPWithResolver rewrites a.com -> b.com,
// then (r == nil, DisableIPv6) re-enters LookupIPv4WithResolver with the rewritten
// host and resolves it via SystemResolver. Proves the rewrite propagates and does
// not double-apply or loop.
func TestLookupIP_DomainRedirect_Reentrant(t *testing.T) {
	withHostsAndIPv6(t, true, func(tree *trie.DomainTrie[HostValue]) {
		insertHost(t, tree, "a.com", "b.com")
	})
	origSystem := SystemResolver
	t.Cleanup(func() { SystemResolver = origSystem })
	SystemResolver = &fakeResolver{m: map[string][]netip.Addr{
		"b.com": {netip.MustParseAddr("1.1.1.1")},
		"a.com": {netip.MustParseAddr("2.2.2.2")},
	}}

	ips, err := LookupIPWithResolver(context.Background(), "a.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("expected redirect a.com -> b.com (1.1.1.1) via SystemResolver, got %v", ips)
	}
}

// a wildcard rule whose redirect target is matched by the same wildcard must not
// hang Hosts.Search; the cycle guard breaks the loop and the terminal target is
// resolved normally. Without the guard this test would hang.
func TestLookupIPv4_WildcardRedirectCycle(t *testing.T) {
	withHostsAndIPv6(t, true, func(tree *trie.DomainTrie[HostValue]) {
		insertHost(t, tree, "+.example.com", "foo.example.com")
	})
	fake := &fakeResolver{m: map[string][]netip.Addr{
		"foo.example.com": {netip.MustParseAddr("1.1.1.1")},
	}}

	ips, err := LookupIPv4WithResolver(context.Background(), "bar.example.com", fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("expected wildcard redirect -> foo.example.com (1.1.1.1), got %v", ips)
	}
}
