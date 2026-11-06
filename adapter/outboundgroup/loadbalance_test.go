package outboundgroup

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	AP "github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/require"
)

const testUrl = "https://www.gstatic.com/generate_204"

func balancedProxies(count int) []C.Proxy {
	proxies := make([]C.Proxy, 0, count)
	for i := 0; i < count; i++ {
		proxies = append(proxies, adapter.NewProxy(outbound.NewDirect()))
	}
	return proxies
}

// The proxies are indistinguishable by name, so identity is the pointer.
func indexOf(t *testing.T, proxies []C.Proxy, selected C.Proxy) int {
	t.Helper()
	for i, proxy := range proxies {
		if proxy == selected {
			return i
		}
	}
	require.Fail(t, "selected proxy is not a member of the group")
	return -1
}

func request(user, host string) *C.Metadata {
	return &C.Metadata{
		NetWork: C.TCP,
		Host:    host,
		DstPort: 443,
		SrcIP:   netip.MustParseAddr("127.0.0.1"),
		InUser:  user,
	}
}

// One unit of work walking several destinations is the case both address-derived
// keys get wrong: the group is meant to hold that work on one egress, and the
// default key changes as soon as the host changes.
func TestLoadBalanceHashKeyInUserSurvivesADestinationChange(t *testing.T) {
	proxies := balancedProxies(8)
	hosts := []string{"a.example.com", "b.example.org", "c.example.net", "d.example.io"}

	byUser := strategyConsistentHashing(testUrl, getKeyWithInUser(getKey))
	pinned := indexOf(t, proxies, byUser(proxies, request("job-1", hosts[0]), false))
	for _, host := range hosts {
		selected := byUser(proxies, request("job-1", host), false)
		require.Equal(t, pinned, indexOf(t, proxies, selected),
			"hash-key: user must ignore the destination")
	}

	// Distinct destination keys are the deterministic contract of the fallback
	// key. Distinct keys may still legally land in the same consistent-hash
	// bucket, so asserting on selected proxy indexes would make this test flaky.
	seenKeys := map[string]struct{}{}
	for _, host := range hosts {
		seenKeys[getKey(request("job-1", host))] = struct{}{}
	}
	require.Len(t, seenKeys, len(hosts),
		"the default key must change with the destination")
}

// Pinning must preserve distinct inbound identities. Consistent hashing may
// legally put several distinct keys in one bucket, so this test checks the
// identity key before hashing instead of asserting a random bucket spread.
func TestLoadBalanceHashKeyInUserKeepsUsersDistinct(t *testing.T) {
	keyed := getKeyWithInUser(getKey)
	users := []string{"job-1", "job-2", "job-3", "job-4", "job-5", "job-6"}

	seenKeys := map[string]struct{}{}
	for _, user := range users {
		seenKeys[keyed(request(user, "a.example.com"))] = struct{}{}
	}
	require.Len(t, seenKeys, len(users))
}

// Sticky sessions keys on source and destination; a client behind one source
// address cannot separate its own concurrent jobs without a supplied identity.
func TestLoadBalanceHashKeyInUserSeparatesJobsSharingASourceAddress(t *testing.T) {
	proxies := balancedProxies(8)
	strategy := newStickySessions(testUrl, getKeyWithInUser(getKeyWithSrcAndDst)).selectProxy

	first := indexOf(t, proxies, strategy(proxies, request("job-1", "a.example.com"), false))
	require.Equal(t, first,
		indexOf(t, proxies, strategy(proxies, request("job-1", "b.example.org"), false)))

	shared := newStickySessions(testUrl, getKeyWithSrcAndDst).selectProxy
	require.Equal(t,
		indexOf(t, proxies, shared(proxies, request("job-1", "a.example.com"), false)),
		indexOf(t, proxies, shared(proxies, request("job-2", "a.example.com"), false)),
		"without a supplied key the two jobs are one session")
}

// An unauthenticated request keeps the strategy's own key. Returning a constant
// instead would herd every anonymous request onto one member.
func TestLoadBalanceHashKeyInUserFallsBackWhenUnauthenticated(t *testing.T) {
	keyed := getKeyWithInUser(getKey)
	require.Equal(t, "example.com", keyed(request("", "a.example.com")))
	require.Equal(t, "job-1", keyed(request("job-1", "a.example.com")))
	require.Equal(t, getKey(nil), keyed(nil))
}

// The option name is the contract with the config file, and nothing else here
// exercises it: every other test reaches the decorator directly, so renaming
// the case would leave them all green while `hash-key: in-user` stopped working.
func TestLoadBalanceHashKeyResolvesTheOptionName(t *testing.T) {
	withInUser, err := hashKey("in-user")
	require.NoError(t, err)
	require.Equal(t, "job-1", withInUser(getKey)(request("job-1", "a.example.com")))

	identity, err := hashKey("")
	require.NoError(t, err)
	require.Equal(t, getKey(request("job-1", "a.example.com")),
		identity(getKey)(request("job-1", "a.example.com")))
}

func TestLoadBalanceHashKeyRejectsUnusableConfigs(t *testing.T) {
	_, err := hashKey("session")
	require.ErrorIs(t, err, errHashKey)

	// `user` was the name this option carried before review. Rejecting it keeps
	// the rename honest: without this the case above could still read `user`
	// and every test here would stay green.
	_, err = hashKey("user")
	require.ErrorIs(t, err, errHashKey)

	_, err = NewLoadBalance(GroupCommonOption{Name: "lb"},
		LoadBalanceOption{Strategy: "round-robin", HashKey: "in-user"}, nil, nil)
	require.ErrorIs(t, err, errHashKey)

	_, err = NewLoadBalance(GroupCommonOption{Name: "lb"},
		LoadBalanceOption{Strategy: "consistent-hashing", HashKey: "nonsense"}, nil, nil)
	require.ErrorIs(t, err, errHashKey)
}

func TestRuleDiagnosticsPreserveStickySessions(t *testing.T) {
	proxies := balancedProxies(2)
	provider, err := AP.NewCompatibleProvider("sticky-test", proxies, AP.NewHealthCheck(proxies, "", 0, 0, true, nil))
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.Close() })
	lb, err := NewLoadBalance(GroupCommonOption{Name: "sticky"}, LoadBalanceOption{Strategy: "sticky-sessions"}, nil, []P.ProxyProvider{provider})
	require.NoError(t, err)
	var evicted []uint64
	lb.sticky.cache = lru.New[uint64, int](lru.WithSize[uint64, int](2), lru.WithEvict[uint64, int](func(key uint64, _ int) { evicted = append(evicted, key) }))
	oldest := request("", "oldest.test")
	newer := request("", "newer.test")
	key := func(m *C.Metadata) uint64 { return utils.MapHash(lb.sticky.keyOf(m)) }
	lb.sticky.cache.Set(key(oldest), 1)
	lb.sticky.cache.Set(key(newer), 0)
	require.Same(t, proxies[1], lb.UnwrapReadOnly(oldest))

	oldRules, oldProviders := tunnel.Rules(), tunnel.RuleProviders()
	oldProxies, oldProxyProviders := tunnel.Proxies(), tunnel.Providers()
	t.Cleanup(func() {
		tunnel.UpdateRules(oldRules, nil, oldProviders)
		tunnel.UpdateProxies(oldProxies, oldProxyProviders)
	})
	rule, err := rules.ParseRule("MATCH", "", "sticky", nil, nil)
	require.NoError(t, err)
	tunnel.UpdateRules([]C.Rule{rule}, nil, nil)
	tunnel.UpdateProxies(map[string]C.Proxy{"sticky": adapter.NewProxy(lb)}, nil)
	for i := 0; i < 5; i++ {
		metadata := request("", fmt.Sprintf("preview-%d.test", i))
		result := tunnel.MatchRules(context.Background(), *metadata, nil, false)
		require.True(t, result.Complete)
		require.Equal(t, "sticky", result.Policy)
		require.False(t, lb.sticky.cache.Exist(key(metadata)))
	}
	require.Empty(t, evicted)
	// Normal touch=false calls must still create sessions, as they did before diagnostics.
	live := request("", "live.test")
	selected := lb.Unwrap(live, false)
	require.Equal(t, []uint64{key(oldest)}, evicted)
	require.Same(t, selected, lb.Unwrap(live, true))
}

type stickyTestProxy struct {
	C.Proxy
	alive bool
}

func (p *stickyTestProxy) AliveForTestUrl(string) bool { return p.alive }

func TestStickyPreviewDoesNotReplaceFailedAssignment(t *testing.T) {
	s := newStickySessions(testUrl, getKey)
	proxies := []C.Proxy{&stickyTestProxy{}, &stickyTestProxy{}}
	metadata := request("", "failed.test")
	key := utils.MapHash(s.keyOf(metadata))
	s.cache.Set(key, 1)
	require.Same(t, proxies[0], s.selectProxy(proxies, metadata, true))
	idx, ok := s.cache.Peek(key)
	require.True(t, ok)
	require.Equal(t, 1, idx)
	require.Same(t, proxies[0], s.selectProxy(proxies, metadata, false))
	idx, ok = s.cache.Peek(key)
	require.True(t, ok)
	require.Zero(t, idx)
}
