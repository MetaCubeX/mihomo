package tunnel

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/sniffer"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	S "github.com/metacubex/mihomo/constant/sniffer"
	RC "github.com/metacubex/mihomo/rules/common"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type udpDestinationTestMapper struct {
	resolver.Enhancer
	hosts map[netip.Addr]string
	fake  netip.Prefix
}

func (m *udpDestinationTestMapper) MappingEnabled() bool { return true }
func (m *udpDestinationTestMapper) IsFakeIP(ip netip.Addr) bool {
	return m.fake.Contains(ip)
}
func (m *udpDestinationTestMapper) FindHostByIP(ip netip.Addr) (string, bool) {
	host, ok := m.hosts[ip]
	return host, ok
}

type udpDestinationTestProxy struct{ C.Proxy }

func (*udpDestinationTestProxy) Type() C.AdapterType              { return C.Direct }
func (*udpDestinationTestProxy) SupportUDP() bool                 { return true }
func (*udpDestinationTestProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

func installUDPDestinationTestState(t *testing.T, entries map[string]string) *udpTestResolver {
	t.Helper()
	// Resolver and routing configuration are process globals, so these tests
	// deliberately remain serial and restore all state after each case.
	oldHosts, oldMapper := resolver.DefaultHosts, resolver.DefaultHostMapper
	oldSystemHosts, oldIPv6 := resolver.UseSystemHosts, resolver.DisableIPv6
	oldRules, oldSubRules, oldProxies, oldMode := rules, subRules, proxies, mode
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	resolver.UseSystemHosts = false
	resolver.DisableIPv6 = true
	resolver.DefaultHostMapper = &udpDestinationTestMapper{
		hosts: map[netip.Addr]string{
			netip.MustParseAddr("198.18.0.1"): "original.example",
			netip.MustParseAddr("192.0.2.1"):  "original.example",
		},
		fake: netip.MustParsePrefix("198.18.0.0/16"),
	}
	proxy := &udpDestinationTestProxy{}
	rules, subRules = nil, nil
	proxies = map[string]C.Proxy{"DIRECT": proxy, "GLOBAL": proxy, "selected": proxy}
	mode = Global
	t.Cleanup(func() {
		resolver.DefaultHosts, resolver.DefaultHostMapper = oldHosts, oldMapper
		resolver.UseSystemHosts, resolver.DisableIPv6 = oldSystemHosts, oldIPv6
		rules, subRules, proxies, mode = oldRules, oldSubRules, oldProxies, oldMode
	})
	for host, value := range entries {
		node, err := resolver.NewHostValue([]string{value})
		require.NoError(t, err)
		require.NoError(t, resolver.DefaultHosts.Insert(host, node))
	}
	r := &udpTestResolver{answer: netip.MustParseAddr("203.0.113.1")}
	installUDPTestResolver(t, r)
	return r
}

func TestUDPDestinationPreservesAddressSemantics(t *testing.T) {
	for _, tc := range []struct {
		name      string
		metadata  C.Metadata
		hosts     map[string]string
		origin    string
		target    string
		routeHost string
		dialHost  string
		direct    bool
	}{
		{name: "Domain", metadata: C.Metadata{Host: "original.example"}, origin: "original.example:443", target: "original.example:443", routeHost: "original.example", dialHost: "original.example"},
		{name: "DomainWithRuleIP", metadata: C.Metadata{Host: "original.example", DstIP: netip.MustParseAddr("203.0.113.1")}, origin: "original.example:443", target: "original.example:443", routeHost: "original.example", dialHost: "original.example"},
		{name: "FakeIP", metadata: C.Metadata{DstIP: netip.MustParseAddr("198.18.0.1")}, origin: "198.18.0.1:443", target: "original.example:443", routeHost: "original.example", dialHost: "original.example"},
		{name: "FakeIPHosts", metadata: C.Metadata{DstIP: netip.MustParseAddr("198.18.0.1")}, hosts: map[string]string{"original.example": "192.0.2.2"}, origin: "198.18.0.1:443", target: "192.0.2.2:443", routeHost: "original.example", dialHost: "original.example"},
		{name: "RedirHost", metadata: C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1")}, origin: "192.0.2.1:443", target: "192.0.2.1:443", routeHost: "original.example", direct: true},
		{name: "RedirHostHosts", metadata: C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1")}, hosts: map[string]string{"original.example": "192.0.2.2"}, origin: "192.0.2.1:443", target: "192.0.2.2:443", routeHost: "original.example", direct: true},
		{name: "RedirHostAlias", metadata: C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1")}, hosts: map[string]string{"original.example": "alias.example"}, origin: "192.0.2.1:443", target: "192.0.2.1:443", routeHost: "alias.example", direct: true},
		{name: "HostsIP", metadata: C.Metadata{Host: "original.example"}, hosts: map[string]string{"original.example": "192.0.2.2"}, origin: "original.example:443", target: "192.0.2.2:443", routeHost: "original.example", dialHost: "original.example"},
		{name: "HostsAlias", metadata: C.Metadata{Host: "original.example"}, hosts: map[string]string{"original.example": "alias.example"}, origin: "original.example:443", target: "alias.example:443", routeHost: "alias.example", dialHost: "alias.example"},
		{name: "HostsAliasToIP", metadata: C.Metadata{Host: "original.example"}, hosts: map[string]string{"original.example": "alias.example", "alias.example": "192.0.2.2"}, origin: "original.example:443", target: "192.0.2.2:443", routeHost: "alias.example", dialHost: "alias.example"},
		{name: "PureMapping", metadata: C.Metadata{Host: "original.example", DstIP: netip.MustParseAddr("192.0.2.3"), DNSMode: C.DNSMapping}, origin: "original.example:443", target: "192.0.2.3:443", routeHost: "original.example"},
		{name: "PureHosts", metadata: C.Metadata{Host: "original.example", DstIP: netip.MustParseAddr("192.0.2.3"), DNSMode: C.DNSHosts}, origin: "original.example:443", target: "192.0.2.3:443", routeHost: "original.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := installUDPDestinationTestState(t, tc.hosts)
			metadata := tc.metadata
			metadata.NetWork, metadata.Type, metadata.DstPort = C.UDP, C.INNER, 443
			original := metadata
			destination := newUDPDestination(&metadata, true, "source")
			require.NoError(t, destination.prepare())
			_, _, err := resolveMetadata(destination.Route)
			require.NoError(t, err)
			dial := destination.dialMetadata()
			require.Equal(t, M.ParseSocksaddr(tc.origin), destination.Origin)
			require.Equal(t, M.ParseSocksaddr(tc.target), destination.Target)
			require.Equal(t, destination.Target, dial.UDP.Target)
			require.Equal(t, tc.routeHost, destination.Route.Host)
			require.Equal(t, tc.dialHost, dial.Host)
			require.Equal(t, tc.direct, destination.direct)
			if destination.Target.IsIP() {
				require.Equal(t, destination.Target.Addr, dial.DstIP)
			}
			require.Equal(t, original, metadata, "the inbound address must survive routing preparation")
			require.Empty(t, r.queries)
		})
	}
}

func TestUDPDestinationRuleResolutionKeepsDomainTarget(t *testing.T) {
	r := installUDPDestinationTestState(t, nil)
	rule, err := RC.NewIPCIDR("203.0.113.0/24", "selected")
	require.NoError(t, err)
	rules, mode = []C.Rule{rule}, Rule
	metadata := &C.Metadata{NetWork: C.UDP, Type: C.INNER, Host: "original.example", DstPort: 443}
	destination := newUDPDestination(metadata, true, "source")
	require.NoError(t, destination.prepare())
	proxy, matched, err := resolveMetadata(destination.Route)
	require.NoError(t, err)
	require.Same(t, proxies["selected"], proxy)
	require.Same(t, rule, matched)
	require.Equal(t, []string{"original.example"}, r.queries)
	require.Equal(t, r.answer, destination.Route.DstIP)
	dial := destination.dialMetadata()
	require.Equal(t, M.ParseSocksaddr("original.example:443"), dial.UDP.Target)
	require.Equal(t, "original.example", dial.Host)
	require.False(t, metadata.DstIP.IsValid())
}

func TestUDPDestinationLaterHostsPacketKeepsLocalSnapshot(t *testing.T) {
	for _, initialIP := range []netip.Addr{{}, netip.MustParseAddr("203.0.113.1")} {
		t.Run(initialIP.String(), func(t *testing.T) {
			r := installUDPDestinationTestState(t, map[string]string{"original.example": "192.0.2.2"})
			metadata := &C.Metadata{
				NetWork: C.UDP, Type: C.INNER, Host: "original.example", DstIP: initialIP, DstPort: 443,
			}
			destination := newUDPDestination(metadata, true, "source")
			require.NoError(t, destination.prepare())
			// Later targets bypass resolveMetadata. Keep the adapter's original
			// resolver input while recording hosts separately for remote policy.
			dial := destination.dialMetadata()
			require.Equal(t, M.ParseSocksaddr("192.0.2.2:443"), dial.UDP.Target)
			require.Equal(t, "original.example", dial.Host)
			require.Equal(t, initialIP, dial.DstIP)
			require.Empty(t, r.queries)
		})
	}
}

func TestUDPDestinationSniffPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		address  string
		host     string
		dnsMode  C.DNSMode
		override bool
		hosts    map[string]string
		target   string
		dialHost string
	}{
		{name: "IPRuleOnly", address: "192.0.2.3:443", target: "192.0.2.3:443"},
		{name: "IPOverride", address: "192.0.2.3:443", override: true, target: "www.google.com:443", dialHost: "www.google.com"},
		{name: "FakeIPRuleOnly", address: "198.18.0.1:443", target: "original.example:443", dialHost: "original.example"},
		{name: "FakeIPOverride", address: "198.18.0.1:443", override: true, target: "www.google.com:443", dialHost: "www.google.com"},
		{name: "RedirHostRuleOnly", address: "192.0.2.1:443", target: "192.0.2.1:443"},
		{name: "RedirHostOverride", address: "192.0.2.1:443", override: true, target: "www.google.com:443", dialHost: "www.google.com"},
		{
			name: "PureMappingRuleOnly", address: "192.0.2.3:443", host: "original.example", dnsMode: C.DNSMapping,
			target: "192.0.2.3:443",
		},
		{
			name: "RuleOnlyIgnoresSniffHosts", address: "198.18.0.1:443", target: "192.0.2.2:443",
			hosts:    map[string]string{"original.example": "192.0.2.2", "www.google.com": "192.0.2.4"},
			dialHost: "original.example",
		},
		{
			name: "OverrideUsesSniffHosts", address: "198.18.0.1:443", override: true, target: "192.0.2.4:443",
			hosts:    map[string]string{"original.example": "192.0.2.2", "www.google.com": "192.0.2.4"},
			dialHost: "www.google.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := installUDPDestinationTestState(t, tc.hosts)
			rule := RC.NewDomain("www.google.com", "selected")
			rules, mode = []C.Rule{rule}, Rule
			address := M.ParseSocksaddr(tc.address)
			metadata := &C.Metadata{
				NetWork: C.UDP, Type: C.INNER, DstIP: address.Addr, DstPort: address.Port,
				Host: tc.host, DNSMode: tc.dnsMode,
			}
			original := *metadata
			destination := newUDPDestination(metadata, true, "source")
			origin := destination.Origin
			dispatcher, err := sniffer.NewDispatcher(&sniffer.Config{
				Enable: true, ParsePureIp: true, ForceDnsMapping: true,
				Sniffers: map[S.Type]sniffer.SnifferConfig{S.QUIC: {OverrideDest: tc.override}},
			})
			require.NoError(t, err)
			payload, err := hex.DecodeString(udpDestinationQUICInitial)
			require.NoError(t, err)
			packet := &udpTestPacket{data: payload}
			adapter := C.NewPacketAdapter(packet, metadata)
			session := newUDPSession(destination)
			sender := dispatcher.UDPSniff(udpSniffPacket{adapter, destination.Route}, session.PacketSender)
			t.Cleanup(sender.Close)
			sender.Send(adapter)
			require.NoError(t, sender.DoSniff(destination.Route))
			require.Equal(t, "www.google.com", destination.Route.SniffHost)
			require.NoError(t, destination.prepare())
			_, matched, err := resolveMetadata(destination.Route)
			require.NoError(t, err)
			require.Same(t, rule, matched, "sniff-only names still select domain rules")
			dial := destination.dialMetadata()
			require.Equal(t, origin, destination.Origin)
			require.Equal(t, M.ParseSocksaddr(tc.target), dial.UDP.Target)
			require.Equal(t, tc.dialHost, dial.Host)
			if dial.UDP.Target.IsIP() {
				require.Equal(t, dial.UDP.Target.Addr, dial.DstIP)
			}
			require.Equal(t, original, *metadata)
			require.Empty(t, r.queries)
			sender.Close()
			require.EqualValues(t, 1, packet.dropped.Load())
		})
	}
}

// Reuse the single-packet Google capture from component/sniffer/sniff_test.go.
// A real Initial packet exercises Dispatcher and QUIC replacement together
// without reproducing the destination-replacement logic in a test stub.
const udpDestinationQUICInitial = "cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55c38890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3e16df1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fddbeadfb0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559757504d158e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e7216b19e54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0b61f1e406b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4fd79d9cb9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d04904b3a61e4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1bb0a4b2bc8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9cec0cf41f0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b540f3d8d98febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf5264e245b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec18670d6db43a1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393df4f3d74bbcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a5836169bf9599eeca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a5e3ba15b906d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb949cb1f40feb7c1d9ce5e71b"
