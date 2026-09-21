package outbound

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
	ovpn "github.com/metacubex/mihomo/transport/openvpn"

	D "github.com/miekg/dns"
)

type openVPNTestResolver struct {
	addresses []netip.Addr
	err       error
	calls     int
	wait      bool
}

func (r *openVPNTestResolver) lookup(ctx context.Context) ([]netip.Addr, error) {
	r.calls++
	if r.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.addresses, r.err
}

func (r *openVPNTestResolver) LookupIP(ctx context.Context, _ string) ([]netip.Addr, error) {
	return r.lookup(ctx)
}

func (r *openVPNTestResolver) LookupIPv4(ctx context.Context, _ string) ([]netip.Addr, error) {
	return r.lookup(ctx)
}

func (r *openVPNTestResolver) LookupIPv6(ctx context.Context, _ string) ([]netip.Addr, error) {
	return r.lookup(ctx)
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

func TestOpenVPNResolverForPushBuildsConfiguredThenPushedDNS(t *testing.T) {
	originalParseNameServer := dns.ParseNameServer
	t.Cleanup(func() { dns.ParseNameServer = originalParseNameServer })
	var parsedServers []string
	dns.ParseNameServer = func(servers []string) ([]dns.NameServer, error) {
		parsedServers = append([]string(nil), servers...)
		return []dns.NameServer{{Net: "udp", Addr: "10.0.0.53:53"}}, nil
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
		t.Fatal("configured and pushed DNS should create a remote resolver chain")
	}
	fallbackResolver, ok := remoteResolver.(*openVPNFallbackResolver)
	if !ok {
		t.Fatalf("unexpected resolver type %T", remoteResolver)
	}
	if len(fallbackResolver.resolvers) != 2 {
		t.Fatalf("expected configured and pushed DNS resolvers, got %d", len(fallbackResolver.resolvers))
	}
	if !slices.Equal(parsedServers, []string{"10.0.0.53"}) {
		t.Fatalf("unexpected pushed DNS servers: %v", parsedServers)
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
	fallbackResolver, ok := remoteResolver.(*openVPNFallbackResolver)
	if !ok {
		t.Fatalf("unexpected resolver type %T", remoteResolver)
	}
	if len(fallbackResolver.resolvers) != 1 {
		t.Fatalf("expected one pushed DNS resolver, got %d", len(fallbackResolver.resolvers))
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

func TestOpenVPNDNSResolverPriority(t *testing.T) {
	originalDefaultResolver := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = originalDefaultResolver })

	explicitAddress := netip.MustParseAddr("192.0.2.10")
	pushedAddress := netip.MustParseAddr("192.0.2.20")
	defaultAddress := netip.MustParseAddr("192.0.2.30")
	testCases := []struct {
		name              string
		explicitAddresses []netip.Addr
		explicitErr       error
		pushedAddresses   []netip.Addr
		pushedErr         error
		expected          netip.Addr
		explicitCalls     int
		pushedCalls       int
		defaultCalls      int
	}{
		{
			name:              "configured DNS succeeds",
			explicitAddresses: []netip.Addr{explicitAddress},
			pushedAddresses:   []netip.Addr{pushedAddress},
			expected:          explicitAddress,
			explicitCalls:     1,
		},
		{
			name:            "configured DNS error uses pushed DNS",
			explicitErr:     resolver.ErrIPNotFound,
			pushedAddresses: []netip.Addr{pushedAddress},
			expected:        pushedAddress,
			explicitCalls:   1,
			pushedCalls:     1,
		},
		{
			name:            "configured DNS empty response uses pushed DNS",
			pushedAddresses: []netip.Addr{pushedAddress},
			expected:        pushedAddress,
			explicitCalls:   1,
			pushedCalls:     1,
		},
		{
			name:          "remote DNS failures use default DNS",
			explicitErr:   resolver.ErrIPNotFound,
			pushedErr:     resolver.ErrIPNotFound,
			expected:      defaultAddress,
			explicitCalls: 1,
			pushedCalls:   1,
			defaultCalls:  1,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			explicitResolver := &openVPNTestResolver{
				addresses: testCase.explicitAddresses,
				err:       testCase.explicitErr,
			}
			pushedResolver := &openVPNTestResolver{
				addresses: testCase.pushedAddresses,
				err:       testCase.pushedErr,
			}
			defaultResolver := &openVPNTestResolver{
				addresses: []netip.Addr{defaultAddress},
			}
			resolver.DefaultResolver = defaultResolver
			remoteResolver := &openVPNFallbackResolver{
				resolvers: []resolver.Resolver{explicitResolver, pushedResolver},
			}

			addresses, err := remoteResolver.LookupIP(context.Background(), "internal.example")
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(addresses, []netip.Addr{testCase.expected}) {
				t.Fatalf("unexpected resolved addresses: %v", addresses)
			}
			if explicitResolver.calls != testCase.explicitCalls {
				t.Fatalf("configured DNS calls = %d, want %d", explicitResolver.calls, testCase.explicitCalls)
			}
			if pushedResolver.calls != testCase.pushedCalls {
				t.Fatalf("pushed DNS calls = %d, want %d", pushedResolver.calls, testCase.pushedCalls)
			}
			if defaultResolver.calls != testCase.defaultCalls {
				t.Fatalf("default DNS calls = %d, want %d", defaultResolver.calls, testCase.defaultCalls)
			}
		})
	}
}

func TestOpenVPNDNSResolverReservesTimeForFallback(t *testing.T) {
	originalDefaultResolver := resolver.DefaultResolver
	defaultResolver := &openVPNTestResolver{
		addresses: []netip.Addr{netip.MustParseAddr("192.0.2.30")},
	}
	resolver.DefaultResolver = defaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = originalDefaultResolver })

	explicitResolver := &openVPNTestResolver{wait: true}
	pushedAddress := netip.MustParseAddr("192.0.2.20")
	pushedResolver := &openVPNTestResolver{addresses: []netip.Addr{pushedAddress}}
	remoteResolver := &openVPNFallbackResolver{
		resolvers: []resolver.Resolver{explicitResolver, pushedResolver},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	addresses, err := remoteResolver.LookupIP(ctx, "internal.example")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(addresses, []netip.Addr{pushedAddress}) {
		t.Fatalf("unexpected resolved addresses: %v", addresses)
	}
	if ctx.Err() != nil {
		t.Fatal("configured DNS exhausted the parent timeout before fallback")
	}
	if explicitResolver.calls != 1 || pushedResolver.calls != 1 || defaultResolver.calls != 0 {
		t.Fatalf(
			"unexpected resolver calls: configured=%d pushed=%d default=%d",
			explicitResolver.calls,
			pushedResolver.calls,
			defaultResolver.calls,
		)
	}
}
