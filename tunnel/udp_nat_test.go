package tunnel

import (
	"fmt"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

var udpNATTestDomainCapabilities = C.UDPCapabilities{
	Destination: C.UDPDomain,
	Reply:       C.UDPReplyAddress,
}

func udpNATRegisterRemote(n *udpNAT, origin, target string) {
	address := M.ParseSocksaddr(target)
	n.register(M.ParseSocksaddr(origin), address, address, false, udpNATTestDomainCapabilities)
}

func udpNATRequireReply(t *testing.T, n *udpNAT, from, want string) {
	t.Helper()
	got, err := n.restore(M.ParseSocksaddr(from))
	require.NoError(t, err)
	require.Equal(t, M.ParseSocksaddr(want), got)
}

func TestUDPNATSingleRemoteOrigin(t *testing.T) {
	for _, origin := range []string{"198.18.0.1:443", "client.example:443"} {
		t.Run(origin, func(t *testing.T) {
			n := newUDPNAT()
			udpNATRegisterRemote(n, origin, "remote.example:443")
			want := M.ParseSocksaddr(origin)
			want.Port = 3478
			got, err := n.restore(M.ParseSocksaddr("[2001:db8::1]:3478"))
			require.NoError(t, err)
			require.Equal(t, want, got)

			// Another port of the same domain/origin is still one origin.
			secondOrigin := M.ParseSocksaddr(origin)
			secondOrigin.Port = 8443
			n.register(secondOrigin, M.ParseSocksaddr("remote.example:8443"), M.ParseSocksaddr("remote.example:8443"), false, udpNATTestDomainCapabilities)
			got, err = n.restore(M.ParseSocksaddr("192.0.2.7:3478"))
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestUDPNATDomainReplies(t *testing.T) {
	n := newUDPNAT()
	udpNATRegisterRemote(n, "198.18.0.1:443", "first.example:443")
	udpNATRegisterRemote(n, "198.18.0.2:443", "Second.Example.:443")
	udpNATRequireReply(t, n, "second.example:443", "198.18.0.2:443")
	udpNATRequireReply(t, n, "SECOND.EXAMPLE.:3478", "198.18.0.2:3478")
	udpNATRequireReply(t, n, "first.example:443", "198.18.0.1:443")

	_, err := n.restore(M.ParseSocksaddr("unknown.example:443"))
	require.ErrorContains(t, err, "unknown UDP reply domain")
}

func TestUDPNATDomainConflictUsesDomainFirstOrigin(t *testing.T) {
	n := newUDPNAT()
	udpNATRegisterRemote(n, "198.18.0.1:443", "unrelated.example:443")
	udpNATRegisterRemote(n, "198.18.0.2:443", "same.example:443")
	udpNATRegisterRemote(n, "198.18.0.3:3478", "SAME.EXAMPLE.:3478")
	udpNATRequireReply(t, n, "same.example:3478", "198.18.0.3:3478")
	udpNATRequireReply(t, n, "same.example:9999", "198.18.0.2:9999")

	udpNATRegisterRemote(n, "198.18.0.4:3478", "same.example:3478")
	// Replies from a domain with several origins go to its first origin, even
	// one registered on another port; the session's first origin belongs to a
	// different domain.
	udpNATRequireReply(t, n, "same.example:3478", "198.18.0.2:3478")
	udpNATRequireReply(t, n, "same.example:443", "198.18.0.2:443")
}

func TestUDPNATPortInferenceAndInvalidation(t *testing.T) {
	n := newUDPNAT()
	udpNATRegisterRemote(n, "198.18.0.1:443", "first.example:443")
	udpNATRegisterRemote(n, "198.18.0.2:3478", "second.example:3478")
	udpNATRequireReply(t, n, "192.0.2.10:3478", "198.18.0.2:3478")
	udpNATRequireReply(t, n, "192.0.2.10:3478", "198.18.0.2:3478")
	// Learning one port must not claim the same IP at every port.
	udpNATRequireReply(t, n, "192.0.2.10:443", "198.18.0.1:443")
	udpNATRequireReply(t, n, "192.0.2.10:9999", "192.0.2.10:9999")

	udpNATRegisterRemote(n, "198.18.0.3:3478", "third.example:3478")
	udpNATRequireReply(t, n, "192.0.2.10:3478", "198.18.0.1:3478")
	udpNATRequireReply(t, n, "192.0.2.11:3478", "198.18.0.1:3478")

	// An unsolicited peer with no matching port is preserved only after
	// multiple domain origins exist (the single-origin case is tested above).
	udpNATRequireReply(t, n, "192.0.2.50:5000", "192.0.2.50:5000")
}

func TestUDPNATDirectIPOverridesMappings(t *testing.T) {
	for _, directFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("direct-first=%t", directFirst), func(t *testing.T) {
			n := newUDPNAT()
			direct := M.ParseSocksaddr("192.0.2.10:5000")
			if directFirst {
				n.register(direct, direct, direct, true, udpNATTestDomainCapabilities)
			}
			udpNATRegisterRemote(n, "198.18.0.1:443", "first.example:443")
			udpNATRegisterRemote(n, "198.18.0.2:3478", "second.example:3478")
			if !directFirst {
				udpNATRequireReply(t, n, "192.0.2.10:3478", "198.18.0.2:3478")
				n.register(direct, direct, direct, true, udpNATTestDomainCapabilities)
			}
			udpNATRequireReply(t, n, "192.0.2.10:3478", "192.0.2.10:3478")
			udpNATRequireReply(t, n, "192.0.2.10:9999", "192.0.2.10:9999")
		})
	}
}

func TestUDPNATLocalResolutionKeepsIPMapping(t *testing.T) {
	n := newUDPNAT()
	capabilities := C.UDPCapabilities{Destination: C.UDPIPOnly, Reply: C.UDPReplyIPOnly}
	ip := M.ParseSocksaddr("192.0.2.10:443")
	n.register(M.ParseSocksaddr("198.18.0.1:443"), M.ParseSocksaddr("first.example:443"), ip, false, capabilities)
	n.register(M.ParseSocksaddr("198.18.0.2:443"), M.ParseSocksaddr("second.example:443"), ip, false, capabilities)
	udpNATRequireReply(t, n, "192.0.2.10:3478", "198.18.0.1:3478")
	udpNATRequireReply(t, n, "192.0.2.11:3478", "192.0.2.11:3478")

	n.register(ip, ip, ip, true, capabilities)
	udpNATRequireReply(t, n, "192.0.2.10:3478", "192.0.2.10:3478")

	withDomainOrigin := newUDPNAT()
	withDomainOrigin.register(M.ParseSocksaddr("client.example:443"), M.ParseSocksaddr("remote.example:443"), ip, false, capabilities)
	udpNATRequireReply(t, withDomainOrigin, "192.0.2.10:443", "192.0.2.10:443")
}

func TestUDPNATBoundDestination(t *testing.T) {
	n := newUDPNAT()
	capabilities := C.UDPCapabilities{Destination: C.UDPDomain, Reply: C.UDPReplyBoundDestination}
	first, second := M.ParseSocksaddr("first.example:443"), M.ParseSocksaddr("second.example:3478")
	n.register(M.ParseSocksaddr("198.18.0.1:443"), first, first, false, capabilities)
	n.register(M.ParseSocksaddr("198.18.0.2:3478"), second, second, false, capabilities)
	udpNATRequireReply(t, n, "second.example:3478", "198.18.0.1:3478")
	udpNATRequireReply(t, n, "192.0.2.7:5000", "198.18.0.1:5000")
}
