package outbound

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type udpPreparationAdapter struct {
	*Base
	resolve func(context.Context, *C.Metadata) error
}

func (a *udpPreparationAdapter) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	return a.resolve(ctx, metadata)
}

type udpLibraryResolver struct {
	resolver.Resolver
	queries []string
}

func (*udpLibraryResolver) Invalid() bool { return true }

func (r *udpLibraryResolver) LookupIPv4(_ context.Context, host string) ([]netip.Addr, error) {
	r.queries = append(r.queries, host)
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestListenPacketContextWithoutUDPRequest(t *testing.T) {
	r := &udpLibraryResolver{}
	previous := resolver.DirectHostResolver
	resolver.DirectHostResolver = r
	t.Cleanup(func() { resolver.DirectHostResolver = previous })
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	metadata := &C.Metadata{
		NetWork: C.UDP, Host: "library.example", DstPort: M.SocksaddrFromNet(server.LocalAddr()).Port,
	}
	proxy := NewDirectWithOption(DirectOption{BasicOption: BasicOption{IPVersion: C.IPv4Only}})
	defer proxy.Close()
	pc, err := proxy.ListenPacketContext(context.Background(), metadata)
	require.NoError(t, err)
	defer pc.Close()
	require.Equal(t, []string{"library.example"}, r.queries)
	require.Equal(t, M.ParseSocksaddrHostPort("library.example", metadata.DstPort), metadata.UDP.Target)
	require.False(t, metadata.UDP.AllowRemote)
	require.Empty(t, metadata.UDP.SessionKey)
	require.Equal(t, M.SocksaddrFromNet(server.LocalAddr()), pc.InitialDestination())
	require.NoError(t, pc.SetDeadline(time.Now().Add(5*time.Second)))
	payload := []byte("legacy UDP library caller")
	_, err = pc.WriteTo(payload, server.LocalAddr())
	require.NoError(t, err)
	buffer := make([]byte, 128)
	n, source, err := server.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, payload, buffer[:n])
	_, err = server.WriteTo(buffer[:n], source)
	require.NoError(t, err)
	n, _, err = pc.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, payload, buffer[:n])
}

func TestPacketConnPrepareUDP(t *testing.T) {
	for _, tc := range []struct {
		name        string
		encoding    C.UDPDestinationEncoding
		allowRemote bool
		target      string
		want        string
		wantResolve int
	}{
		{"remote domain", C.UDPDomain, true, "Target.Example.:443", "Target.Example.:443", 0},
		{"remote fixed IP", C.UDPDomain, true, "192.0.2.2:443", "192.0.2.2:443", 0},
		{"remote unmaps IP", C.UDPDomain, true, "[::ffff:192.0.2.2]:443", "192.0.2.2:443", 0},
		{"explicit local", C.UDPDomain, false, "target.example:443", "192.0.2.3:443", 1},
		{"IP-only protocol", C.UDPIPOnly, true, "target.example:443", "192.0.2.3:443", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			adapter := &udpPreparationAdapter{
				Base: NewBase(BaseOption{Name: "selected", Type: C.Direct}),
				resolve: func(_ context.Context, metadata *C.Metadata) error {
					calls++
					// Preserve the local snapshot even when rule resolution already supplied an IP.
					require.Equal(t, "route.example", metadata.Host)
					require.Equal(t, netip.MustParseAddr("192.0.2.1"), metadata.DstIP)
					metadata.DstIP = netip.MustParseAddr("192.0.2.3")
					metadata.UDP.Target = M.ParseSocksaddr("changed.example:53")
					return nil
				},
			}
			metadata := &C.Metadata{
				NetWork: C.UDP,
				Host:    "route.example",
				DstIP:   netip.MustParseAddr("192.0.2.1"),
				DstPort: 443,
				UDP:     &C.UDPRequest{Target: M.ParseSocksaddr(tc.target), AllowRemote: tc.allowRemote},
			}
			capabilities := C.UDPCapabilities{Destination: tc.encoding, Reply: C.UDPReplyAddress}
			pc, err := NewPacketConn(&nopPacketConn{}, adapter, metadata, capabilities)
			require.NoError(t, err)
			t.Cleanup(func() { _ = pc.Close() })
			initial := pc.InitialDestination()
			wantInitial := M.ParseSocksaddr("192.0.2.1:443")
			if tc.allowRemote && tc.encoding == C.UDPDomain {
				wantInitial = M.ParseSocksaddr(tc.want)
			}
			require.Equal(t, wantInitial, initial)
			require.Zero(t, calls, "construction must not repeat initial preparation")

			// Later requests and mutable caller state cannot change this connection's policy.
			metadata.UDP.AllowRemote = !tc.allowRemote
			capabilities.Destination = C.UDPIPOnly
			prepared, err := pc.PrepareUDP(context.Background(), metadata)
			require.NoError(t, err)
			require.Equal(t, M.ParseSocksaddr(tc.want), prepared)
			require.Equal(t, tc.wantResolve, calls)
			require.Equal(t, M.ParseSocksaddr(tc.target), metadata.UDP.Target)
			require.Equal(t, netip.MustParseAddr("192.0.2.1"), metadata.DstIP)
			require.Equal(t, tc.encoding, pc.UDPCapabilities().Destination)
			metadata.DstIP = netip.MustParseAddr("192.0.2.4")
			metadata.UDP.Target = M.ParseSocksaddr("mutated.example:53")
			require.Equal(t, initial, pc.InitialDestination())
		})
	}
}
