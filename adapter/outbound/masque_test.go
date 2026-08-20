package outbound

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewStandardMASQUE(t *testing.T) {
	outbound, err := NewMasque(MasqueOption{
		Name:    "standard-masque",
		Server:  "proxy.example",
		Port:    443,
		Ip:      "192.0.2.2",
		Network: "h2",
		Headers: map[string]string{"Authorization": "Bearer token"},
	})
	require.NoError(t, err)
	defer outbound.Close()
	require.NotNil(t, outbound.h2Transport)
	require.Zero(t, outbound.quicDialOpt.ConnectionIDLength, "Cloudflare's connection-ID override must not leak into standard MASQUE")
}

func TestStandardMASQUERejectsLegacyWARPKey(t *testing.T) {
	_, err := NewMasque(MasqueOption{
		Name:      "legacy",
		Server:    "proxy.example",
		Port:      443,
		Ip:        "192.0.2.2",
		PublicKey: "legacy-warp-key",
	})
	require.ErrorContains(t, err, "use type: warp")
}

func TestMASQUEClientRoutes(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")}
	routes, err := masqueClientRoutes(prefixes, []string{"2001:db8::/126", "198.51.100.0/24"})
	require.NoError(t, err)
	require.Len(t, routes, 2)
	// RFC 9484 requires IPv4 ranges before IPv6 ranges, regardless of the
	// configuration order.
	require.Equal(t, netip.MustParseAddr("198.51.100.0"), routes[0].StartIP)
	require.Equal(t, netip.MustParseAddr("198.51.100.255"), routes[0].EndIP)
	require.Equal(t, netip.MustParseAddr("2001:db8::"), routes[1].StartIP)
	require.Equal(t, netip.MustParseAddr("2001:db8::3"), routes[1].EndIP)

	routes, err = masqueClientRoutes(prefixes, nil)
	require.NoError(t, err)
	require.Equal(t, prefixes[0].Addr(), routes[0].StartIP)
	require.Equal(t, prefixes[0].Addr(), routes[0].EndIP)
}

func TestMASQUEClientRoutesRejectOverlap(t *testing.T) {
	_, err := masqueClientRoutes(nil, []string{"198.51.100.0/24", "198.51.100.128/25"})
	require.ErrorContains(t, err, "overlap")

	routes, err := masqueClientRoutes(nil, []string{"198.51.100.0/24", "2001:db8::/32"})
	require.NoError(t, err, "the same numeric protocol may be advertised once per IP version")
	require.Len(t, routes, 2)
}

func TestStandardMASQUERejectsConfiguredPseudoHeader(t *testing.T) {
	_, err := NewMasque(MasqueOption{
		Name:    "bad-headers",
		Server:  "proxy.example",
		Port:    443,
		Ip:      "192.0.2.2",
		Headers: map[string]string{":authority": "elsewhere.example"},
	})
	require.ErrorContains(t, err, "pseudo-header")
}
