package inbound_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
	"github.com/stretchr/testify/require"
)

type udpDomainTestResolver struct {
	resolver.Resolver
	mu      sync.Mutex
	queries []string
	answer  netip.Addr
}

func (r *udpDomainTestResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, host)
	if !r.answer.IsValid() {
		return nil, resolver.ErrIPNotFound
	}
	return []netip.Addr{r.answer}, nil
}

func (r *udpDomainTestResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

func (r *udpDomainTestResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	_, _ = r.LookupIP(ctx, host)
	return nil, resolver.ErrIPNotFound
}

func (*udpDomainTestResolver) Invalid() bool { return true }

func installUDPDomainTestResolver(t *testing.T, answer netip.Addr) *udpDomainTestResolver {
	t.Helper()
	r := &udpDomainTestResolver{answer: answer}
	previous := resolver.DefaultResolver
	// Keep these tests serial: the real adapters consult the shared resolver.
	resolver.DefaultResolver = r
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	return r
}

func (r *udpDomainTestResolver) checkQueries(t *testing.T, want []string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.Equal(t, want, r.queries)
}

func udpDomainTestPairs() []udpTestPair {
	pairs := []udpTestPair{udpTestPairs[0], udpTestPairs[1]}
	for _, cipher := range []struct {
		name     string
		method   string
		password string
	}{
		{name: "None", method: "none", password: userUUID},
		{name: "Stream", method: "aes-128-cfb", password: userUUID},
		{name: "AEAD", method: "aes-128-gcm", password: userUUID},
		{name: "2022AES", method: "2022-blake3-aes-128-gcm", password: shadowsocksPassword16},
		{name: "2022ChaCha", method: "2022-blake3-chacha20-poly1305", password: shadowsocksPassword32},
	} {
		for _, transport := range []struct {
			name    string
			version int
		}{
			{name: "Native"},
			{name: "UoTv1", version: uot.LegacyVersion},
			{name: "UoTv2", version: uot.Version},
		} {
			cipher, transport := cipher, transport
			pairs = append(pairs, udpTestPair{
				name:         "Shadowsocks" + cipher.name + "/" + transport.name,
				local:        transport.version == uot.LegacyVersion,
				udpTransport: transport.version == 0,
				in: func(base inbound.BaseOption) (C.InboundListener, error) {
					return inbound.NewShadowSocks(&inbound.ShadowSocksOption{
						BaseOption: base, Cipher: cipher.method, Password: cipher.password, UDP: transport.version == 0,
					})
				},
				out: func(address netip.AddrPort, basic outbound.BasicOption) (C.ProxyAdapter, error) {
					return outbound.NewShadowSocks(outbound.ShadowSocksOption{
						BasicOption: basic, Name: "udp_domain_outbound", Server: address.Addr().String(), Port: int(address.Port()),
						Cipher: cipher.method, Password: cipher.password, UDP: true,
						UDPOverTCP: transport.version != 0, UDPOverTCPVersion: transport.version,
					})
				},
			})
		}
	}
	pairs = append(pairs, udpTestPair{name: "SSR", peer: newUDPSSRPeer})
	pairs = append(pairs, udpTestPair{
		name: "Snell", ipReply: true,
		in: func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewSnell(&inbound.SnellOption{BaseOption: base, Psk: userUUID, Version: 4, UDP: true})
		},
		out: func(address netip.AddrPort, basic outbound.BasicOption) (C.ProxyAdapter, error) {
			return outbound.NewSnell(outbound.SnellOption{BasicOption: basic, Name: "udp_snell", Server: address.Addr().String(), Port: int(address.Port()), Psk: userUUID, Version: 4, UDP: true})
		},
	})
	pairs = append(pairs, udpQUICDomainTestPairs()...)
	return pairs
}

func udpDomainTestMetadata(target M.Socksaddr, allowRemote bool) *C.Metadata {
	return &C.Metadata{
		NetWork: C.UDP, Host: target.Fqdn, DstIP: target.Addr, DstPort: target.Port,
		UDP: &C.UDPRequest{Target: target, AllowRemote: allowRemote},
	}
}

func udpDomainTestAddress(address M.Socksaddr) net.Addr {
	if address.IsIP() {
		return address.UDPAddr()
	}
	return address
}

func exchangeUDPDomainTestPacket(t *testing.T, pc C.PacketConn, results <-chan udpEchoResult, target, reply M.Socksaddr, wait bool) {
	t.Helper()
	payload := []byte("domain UDP payload")
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(3*time.Second)))
	// UoT v1 reports the encoded frame length; verify the delivered payload below.
	_, err := pc.WriteTo(payload, udpDomainTestAddress(target))
	require.NoError(t, err)
	data, source, err := readUDPTestPacket(pc, wait)
	require.NoError(t, err)
	require.Equal(t, payload, data)
	require.Equal(t, reply, M.SocksaddrFromNet(source))
	select {
	case result := <-results:
		require.NoError(t, result.err)
		require.Equal(t, payload, result.data)
		require.Equal(t, C.UDP, result.metadata.NetWork)
		require.Equal(t, target.Fqdn, result.metadata.Host, "the server must receive the business domain unchanged")
		require.Equal(t, target.Addr, result.metadata.DstIP)
		require.Equal(t, target.Port, result.metadata.DstPort)
	case <-time.After(3 * time.Second):
		t.Fatal("UDP echo handler did not finish")
	}
}

func TestInboundUDPDomainResolution(t *testing.T) {
	// One fixture exercises permission, actual wire targets and both read APIs.
	// Queries are recorded only for business domains; peers use literal IPs.
	for _, pair := range udpDomainTestPairs() {
		for _, remote := range []bool{false, true} {
			name := "local"
			if remote {
				name = "remote"
			}
			t.Run(pair.name+"/"+name, func(t *testing.T) {
				answer := netip.MustParseAddr("192.0.2.1")
				r := installUDPDomainTestResolver(t, answer)
				out, results := newUDPTestPair(t, pair, func(metadata *C.Metadata) net.Addr {
					if pair.ipReply {
						return M.ParseSocksaddr("192.0.2.50:20001").UDPAddr()
					}
					return udpDomainTestAddress(M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				targets := []M.Socksaddr{M.ParseSocksaddr("First.udp-remote.invalid:10001"), M.ParseSocksaddr("Second.udp-remote.invalid:10002")}
				if pair.bound {
					targets = targets[:1]
				}
				pc, err := out.ListenPacketContext(ctx, udpDomainTestMetadata(targets[0], remote))
				require.NoError(t, err)
				t.Cleanup(func() { _ = pc.Close() })
				encoding := C.UDPDomain
				if pair.local {
					encoding = C.UDPIPOnly
				}
				require.Equal(t, encoding, pc.UDPCapabilities().Destination)
				if pair.ipReply {
					require.Equal(t, C.UDPReplyIPOnly, pc.UDPCapabilities().Reply)
				}
				var queries []string
				if !remote || pair.local {
					queries = append(queries, targets[0].Fqdn)
				}
				for _, wait := range []bool{false, true} {
					for _, target := range targets {
						want := target
						if !remote || pair.local {
							want = M.Socksaddr{Addr: answer, Port: target.Port}
							queries = append(queries, target.Fqdn)
						}
						prepared, err := pc.PrepareUDP(ctx, udpDomainTestMetadata(target, remote))
						require.NoError(t, err)
						require.Equal(t, want, prepared)
						if target == targets[0] {
							require.Equal(t, want, pc.InitialDestination())
						}
						reply := want
						if pair.ipReply {
							reply = M.ParseSocksaddr("192.0.2.50:20001")
						}
						exchangeUDPDomainTestPacket(t, pc, results, prepared, reply, wait)
					}
				}
				r.checkQueries(t, queries)
			})
		}
	}
}

// Reuse the remote/local checks and echo handler so these transports must
// preserve the same per-packet addresses as the SOCKS and Shadowsocks peers.
func udpQUICDomainTestPairs() []udpTestPair {
	pairs := []udpTestPair{
		{
			name:         "Hysteria2",
			udpTransport: true,
			in: func(base inbound.BaseOption) (C.InboundListener, error) {
				return inbound.NewHysteria2(&inbound.Hysteria2Option{
					BaseOption: base, Users: map[string]string{"test": userUUID},
					Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
				})
			},
			out: func(address netip.AddrPort, basic outbound.BasicOption) (C.ProxyAdapter, error) {
				return outbound.NewHysteria2(outbound.Hysteria2Option{
					BasicOption: basic, Name: "udp_domain_outbound", Server: address.Addr().String(), Port: int(address.Port()),
					Password: userUUID, Fingerprint: tlsFingerprint,
				})
			},
		},
		{
			name: "AnyTLS",
			in: func(base inbound.BaseOption) (C.InboundListener, error) {
				return inbound.NewAnyTLS(&inbound.AnyTLSOption{
					BaseOption: base, Users: map[string]string{"test": userUUID},
					Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
				})
			},
			out: func(address netip.AddrPort, basic outbound.BasicOption) (C.ProxyAdapter, error) {
				return outbound.NewAnyTLS(outbound.AnyTLSOption{
					BasicOption: basic, Name: "udp_domain_outbound", Server: address.Addr().String(), Port: int(address.Port()),
					Password: userUUID, Fingerprint: tlsFingerprint, UDP: true,
				})
			},
		},
		{
			name: "Sudoku",
			in: func(base inbound.BaseOption) (C.InboundListener, error) {
				return inbound.NewSudoku(&inbound.SudokuOption{BaseOption: base, Key: userUUID})
			},
			out: func(address netip.AddrPort, basic outbound.BasicOption) (C.ProxyAdapter, error) {
				return outbound.NewSudoku(outbound.SudokuOption{
					BasicOption: basic, Name: "udp_domain_outbound", Server: address.Addr().String(), Port: int(address.Port()), Key: userUUID,
				})
			},
		},
	}
	for _, version := range []int{4, 5} {
		for _, mode := range []struct {
			name  string
			relay string
			uos   int
		}{
			{name: "native", relay: "native"},
			{name: "quic", relay: "quic"},
			{name: "UoSv1", uos: 1},
			{name: "UoSv2", uos: 2},
		} {
			version, mode := version, mode
			pairs = append(pairs, udpTestPair{
				name:         fmt.Sprintf("TUICv%d/%s", version, mode.name),
				local:        mode.uos == 1,
				udpTransport: true,
				in: func(base inbound.BaseOption) (C.InboundListener, error) {
					return inbound.NewTuic(&inbound.TuicOption{
						BaseOption: base, Token: []string{userUUID}, Users: map[string]string{userUUID: userUUID},
						Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, AuthenticationTimeout: 5000,
					})
				},
				out: func(address netip.AddrPort, basic outbound.BasicOption) (C.ProxyAdapter, error) {
					option := outbound.TuicOption{
						BasicOption: basic, Name: "udp_domain_outbound", Server: address.Addr().String(), Port: int(address.Port()),
						Fingerprint: tlsFingerprint, UdpRelayMode: mode.relay,
						UDPOverStream: mode.uos != 0, UDPOverStreamVersion: mode.uos,
					}
					if version == 4 {
						option.Token = userUUID
					} else {
						option.UUID, option.Password = userUUID, userUUID
					}
					return outbound.NewTuic(option)
				},
			})
		}
	}
	for _, version := range []string{"v1", "v2"} {
		for _, stream := range []bool{false, true} {
			version, stream := version, stream
			mode := "datagram"
			if stream {
				mode = "stream"
			}
			pairs = append(pairs, udpTestPair{
				name:         "ShadowQUIC/" + version + "/" + mode,
				udpTransport: true,
				in: func(base inbound.BaseOption) (C.InboundListener, error) {
					return inbound.NewShadowQuic(&inbound.ShadowQuicOption{
						BaseOption: base, QUICVersions: []string{version},
						Users:       []inbound.ShadowQuicUser{{Username: "udp-domain-user", Password: userUUID}},
						JLSUpstream: inbound.ShadowQuicJLSUpstream{Addr: "127.0.0.1:1"},
					})
				},
				out: func(address netip.AddrPort, basic outbound.BasicOption) (C.ProxyAdapter, error) {
					return outbound.NewShadowQuic(outbound.ShadowQuicOption{
						BasicOption: basic, Name: "udp_domain_outbound", Server: address.Addr().String(), Port: int(address.Port()),
						QUICVersions: []string{version}, UDPOverStream: stream, Username: "udp-domain-user", Password: userUUID,
					})
				},
			})
		}
	}
	return append(pairs, udpTestPair{name: "Hysteria", peer: newUDPHysteriaPeer})
}
