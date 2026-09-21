package outbound

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
	ovpn "github.com/metacubex/mihomo/transport/openvpn"

	D "github.com/miekg/dns"
)

type openVPNTestResolver struct {
	addresses []netip.Addr
	err       error
	calls     int
}

func (r *openVPNTestResolver) lookup() ([]netip.Addr, error) {
	r.calls++
	return r.addresses, r.err
}

func (r *openVPNTestResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return r.lookup()
}

func (r *openVPNTestResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return r.lookup()
}

func (r *openVPNTestResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return r.lookup()
}

func (r *openVPNTestResolver) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, r.err
}

func (r *openVPNTestResolver) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, r.err
}

func (r *openVPNTestResolver) Invalid() bool {
	return true
}

func (r *openVPNTestResolver) ClearCache() {}

func (r *openVPNTestResolver) ResetConnection() {}

func TestOpenVPNResolverForPushDisabled(t *testing.T) {
	openVPN := &OpenVPN{
		option: &OpenVPNOption{RemoteDnsResolve: false},
		dns:    []dns.NameServer{{Net: "udp", Addr: "1.1.1.1:53"}},
	}

	remoteResolver, err := openVPN.resolverForPush(&ovpn.PushReply{
		DNS: []netip.Addr{netip.MustParseAddr("10.0.0.53")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if remoteResolver != nil {
		t.Fatal("remote DNS resolver should be disabled")
	}
}

func TestOpenVPNResolverForPushPrefersConfiguredDNS(t *testing.T) {
	originalParseNameServer := dns.ParseNameServer
	t.Cleanup(func() { dns.ParseNameServer = originalParseNameServer })
	dns.ParseNameServer = func([]string) ([]dns.NameServer, error) {
		t.Fatal("pushed DNS should not be parsed when configured DNS is available")
		return nil, nil
	}

	openVPN := &OpenVPN{
		option: &OpenVPNOption{RemoteDnsResolve: true},
		dns:    []dns.NameServer{{Net: "udp", Addr: "1.1.1.1:53"}},
	}

	remoteResolver, err := openVPN.resolverForPush(&ovpn.PushReply{
		DNS: []netip.Addr{netip.MustParseAddr("10.0.0.53")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if remoteResolver == nil {
		t.Fatal("configured DNS should create a remote resolver")
	}
	if openVPN.dns[0].ProxyAdapter != nil {
		t.Fatal("configured DNS should not be mutated")
	}
}

func TestOpenVPNResolverForPushUsesPushedDNS(t *testing.T) {
	originalParseNameServer := dns.ParseNameServer
	t.Cleanup(func() { dns.ParseNameServer = originalParseNameServer })

	var parsedServers []string
	dns.ParseNameServer = func(servers []string) ([]dns.NameServer, error) {
		parsedServers = append([]string(nil), servers...)
		nameServers := make([]dns.NameServer, 0, len(servers))
		for _, server := range servers {
			address := netip.MustParseAddr(server)
			nameServers = append(nameServers, dns.NameServer{
				Net:  "udp",
				Addr: net.JoinHostPort(address.String(), "53"),
			})
		}
		return nameServers, nil
	}

	openVPN := &OpenVPN{option: &OpenVPNOption{RemoteDnsResolve: true}}
	remoteResolver, err := openVPN.resolverForPush(&ovpn.PushReply{
		DNS: []netip.Addr{
			netip.MustParseAddr("10.0.0.53"),
			netip.MustParseAddr("2001:db8::53"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if remoteResolver == nil {
		t.Fatal("pushed DNS should create a remote resolver")
	}
	if !slices.Equal(parsedServers, []string{"10.0.0.53", "2001:db8::53"}) {
		t.Fatalf("unexpected pushed DNS servers: %v", parsedServers)
	}
}

func TestOpenVPNResolverForPushFallsBackToDefaultDNS(t *testing.T) {
	openVPN := &OpenVPN{option: &OpenVPNOption{RemoteDnsResolve: true}}

	remoteResolver, err := openVPN.resolverForPush(&ovpn.PushReply{})
	if err != nil {
		t.Fatal(err)
	}
	if remoteResolver != nil {
		t.Fatal("missing configured and pushed DNS should use the default resolver")
	}
}

func TestOpenVPNRemoteDNSFailureFallsBack(t *testing.T) {
	originalDefaultResolver := resolver.DefaultResolver
	defaultResolver := &openVPNTestResolver{
		addresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")},
	}
	resolver.DefaultResolver = defaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = originalDefaultResolver })

	testCases := []struct {
		name      string
		addresses []netip.Addr
		err       error
	}{
		{name: "query error", err: resolver.ErrIPNotFound},
		{name: "empty response"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			primaryResolver := &openVPNTestResolver{
				addresses: testCase.addresses,
				err:       testCase.err,
			}
			remoteResolver := &openVPNFallbackResolver{primary: primaryResolver}
			defaultCalls := defaultResolver.calls

			addresses, err := remoteResolver.LookupIP(context.Background(), "internal.example")
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(addresses, defaultResolver.addresses) {
				t.Fatalf("unexpected fallback addresses: %v", addresses)
			}
			if primaryResolver.calls == 0 {
				t.Fatal("remote DNS resolver was not queried")
			}
			if defaultResolver.calls != defaultCalls+1 {
				t.Fatalf("default resolver should be queried once, got %d new calls", defaultResolver.calls-defaultCalls)
			}
		})
	}
}
