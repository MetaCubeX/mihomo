package outboundgroup

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"

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
	strategy := strategyStickySessions(testUrl, getKeyWithInUser(getKeyWithSrcAndDst))

	first := indexOf(t, proxies, strategy(proxies, request("job-1", "a.example.com"), false))
	require.Equal(t, first,
		indexOf(t, proxies, strategy(proxies, request("job-1", "b.example.org"), false)))

	shared := strategyStickySessions(testUrl, getKeyWithSrcAndDst)
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

// deadProxy fails its health check, so every strategy must skip it.
type deadProxy struct{ C.Proxy }

func (deadProxy) AliveForTestUrl(string) bool { return false }

func countPicks(t *testing.T, lc *leastConnections, proxies []C.Proxy, n int) ([]int, []func()) {
	t.Helper()
	counts := make([]int, len(proxies))
	releases := make([]func(), 0, n)
	for i := 0; i < n; i++ {
		proxy, release := lc.pick(proxies, testUrl, true)
		counts[indexOf(t, proxies, proxy)]++
		releases = append(releases, release)
	}
	return counts, releases
}

// Connections of one destination must spread: this is the case the hashing
// strategies cannot serve and the reason the strategy exists.
func TestLoadBalanceLeastConnectionsSpreadsOpenConnections(t *testing.T) {
	proxies := balancedProxies(3)
	counts, _ := countPicks(t, newLeastConnections(), proxies, 9)
	require.Equal(t, []int{3, 3, 3}, counts)
}

func TestLoadBalanceLeastConnectionsReusesAReleasedMember(t *testing.T) {
	proxies := balancedProxies(3)
	lc := newLeastConnections()
	first, release := lc.pick(proxies, testUrl, true)
	_, _ = countPicks(t, lc, proxies, 2) // one connection on every member

	release()
	release() // a second release must not free a connection that is still open
	next, _ := lc.pick(proxies, testUrl, true)
	require.Same(t, first, next, "the only member below the others must get the next connection")

	_, _ = countPicks(t, lc, proxies, 3) // two on every member again
	require.Equal(t, map[C.Proxy]int{proxies[0]: 2, proxies[1]: 2, proxies[2]: 2}, lc.active)
}

// A member listed twice holds two shares, the same weighting round-robin
// already gives a repeated name.
func TestLoadBalanceLeastConnectionsWeighsARepeatedMember(t *testing.T) {
	members := balancedProxies(2)
	fast, slow := members[0], members[1]
	proxies := []C.Proxy{fast, fast, slow}
	lc := newLeastConnections()
	got := map[C.Proxy]int{}
	for i := 0; i < 6; i++ {
		proxy, _ := lc.pick(proxies, testUrl, true)
		got[proxy]++
	}
	require.Equal(t, 4, got[fast])
	require.Equal(t, 2, got[slow])
}

func TestLoadBalanceLeastConnectionsSkipsADeadMember(t *testing.T) {
	alive := balancedProxies(2)
	dead := deadProxy{balancedProxies(1)[0]}
	proxies := []C.Proxy{dead, alive[0], alive[1]}
	counts, _ := countPicks(t, newLeastConnections(), proxies, 4)
	require.Equal(t, []int{0, 2, 2}, counts)

	// With nobody alive the group still answers, like every other strategy.
	allDead := []C.Proxy{deadProxy{alive[0]}, deadProxy{alive[1]}}
	proxy, _ := newLeastConnections().pick(allDead, testUrl, true)
	require.Equal(t, allDead[0], proxy)
}

// Unwrap reports a member without opening anything, so it must not count.
func TestLoadBalanceLeastConnectionsReportingDoesNotCount(t *testing.T) {
	proxies := balancedProxies(2)
	lc := newLeastConnections()
	for i := 0; i < 5; i++ {
		_, release := lc.pick(proxies, testUrl, false)
		release()
	}
	require.Empty(t, lc.active)
}

func TestLoadBalanceLeastConnectionsRejectsAHashKey(t *testing.T) {
	_, err := NewLoadBalance(GroupCommonOption{Name: "lb"},
		LoadBalanceOption{Strategy: "least-connections", HashKey: "in-user"}, nil, nil)
	require.ErrorIs(t, err, errHashKey)

	lb, err := NewLoadBalance(GroupCommonOption{Name: "lb"},
		LoadBalanceOption{Strategy: "least-connections"}, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, lb.leastConn)
}
