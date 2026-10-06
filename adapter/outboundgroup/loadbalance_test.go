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
