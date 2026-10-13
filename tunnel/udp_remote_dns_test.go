package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	M "github.com/metacubex/sing/common/metadata"
)

type udpReply struct {
	data []byte
	addr net.Addr
}
type mappingPacketConn struct {
	C.PacketConn
	replies  []udpReply
	sent     net.Addr
	freed    int
	closed   bool
	resolves int
	domains  []string
	localIP  netip.Addr
}

func (p *mappingPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	if len(p.replies) == 0 {
		return nil, nil, nil, io.EOF
	}
	reply := p.replies[0]
	p.replies = p.replies[1:]
	return reply.data, func() { p.freed++ }, reply.addr, nil
}
func (p *mappingPacketConn) PrepareUDP(ctx context.Context, m *C.Metadata) error {
	p.resolves++
	first, scoped := C.UDPRemoteDNSDomainFromContext(ctx)
	if !scoped {
		return errors.New("missing session domain scope")
	}
	p.domains = append(p.domains, first)
	if m.Host != first && p.localIP.IsValid() {
		m.DstIP = p.localIP
	}
	return nil
}
func (p *mappingPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.sent = addr
	return len(b), nil
}
func (*mappingPacketConn) SetReadDeadline(time.Time) error { return nil }
func (p *mappingPacketConn) Close() error                  { p.closed = true; return nil }

type mappingWriteBack struct{ replies []udpReply }

func (w *mappingWriteBack) WriteBack(data []byte, addr net.Addr) (int, error) {
	w.replies = append(w.replies, udpReply{append([]byte(nil), data...), addr})
	return len(data), nil
}

type domainPacket struct {
	metadata *C.Metadata
	dropped  bool
}

func (p *domainPacket) Data() []byte { return []byte("request") }
func (p *domainPacket) Drop()        { p.dropped = true }
func (*domainPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (*domainPacket) WriteBack(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (p *domainPacket) Metadata() *C.Metadata                     { return p.metadata }
func (*domainPacket) Key() string                                 { return "remote-dns-test" }

func TestUDPDomainReplyPreservesPort(t *testing.T) {
	for _, originIP := range []string{"198.18.0.1", "2001:db8::1"} {
		t.Run(originIP, func(t *testing.T) {
			s := newPacketSender().(*packetSender)
			origin := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr(originIP), DstPort: 443}
			s.AddMapping(origin, &C.Metadata{NetWork: C.UDP, Host: "example.invalid", DstPort: 443})
			pc := &mappingPacketConn{replies: []udpReply{
				{[]byte("first"), M.ParseSocksaddr("example.invalid:443")},
				{[]byte("second"), M.ParseSocksaddr("example.invalid:8443")},
				{[]byte("third"), M.ParseSocksaddr("example.invalid:443")},
			}}
			wb := &mappingWriteBack{}
			handleUDPToLocal(wb, pc, s, "domain-reply-port-test", origin.AddrPort())
			if len(wb.replies) != 3 {
				t.Fatalf("got %d replies, want 3", len(wb.replies))
			}
			for i, port := range []uint16{443, 8443, 443} {
				want := netip.AddrPortFrom(origin.DstIP, port).String()
				if wb.replies[i].addr.String() != want {
					t.Fatalf("reply %d: got %s, want %s", i, wb.replies[i].addr, want)
				}
			}
			if pc.freed != 3 || !pc.closed {
				t.Fatal("reply resources not released")
			}
		})
	}
}

func TestUDPDomainReplyWithoutOriginIP(t *testing.T) {
	s := newPacketSender().(*packetSender)
	origin := &C.Metadata{NetWork: C.UDP, Host: "example.invalid", DstPort: 443}
	s.AddMapping(origin, origin.Clone())
	if origin.AddrPort().IsValid() {
		t.Fatal("domain-only origin unexpectedly has an IP")
	}
	wants := []string{"example.invalid:443", "example.invalid:8443"}
	pc := &mappingPacketConn{replies: []udpReply{
		{[]byte("first"), M.ParseSocksaddr(wants[0])},
		{[]byte("second"), M.ParseSocksaddr(wants[1])},
	}}
	wb := &mappingWriteBack{}
	handleUDPToLocal(wb, pc, s, "domain-only-reply-test", origin.AddrPort())
	if len(wb.replies) != len(wants) {
		t.Fatalf("got %d replies, want %d", len(wb.replies), len(wants))
	}
	for i, want := range wants {
		if wb.replies[i].addr.String() != want {
			t.Fatalf("reply %d: got %s, want %s", i, wb.replies[i].addr, want)
		}
		// Use the same address encoding as the SOCKS5 inbound's WriteBack.
		encoded, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(wb.replies[i].addr), wb.replies[i].data)
		if err != nil {
			t.Fatal(err)
		}
		addr, payload, err := socks5.DecodeUDPPacket(encoded)
		if err != nil || addr.String() != want || string(payload) != []string{"first", "second"}[i] {
			t.Fatalf("SOCKS5 reply %d: address %v, payload %q, error %v", i, addr, payload, err)
		}
	}
	if pc.freed != len(wants) || !pc.closed {
		t.Fatal("reply resources not released")
	}
}

func TestUDPRemoteDNSFirstPacket(t *testing.T) {
	for _, initialHost := range []string{"", "first.invalid", "fake-ip"} {
		t.Run("initial="+initialHost, func(t *testing.T) {
			s := newPacketSender().(*packetSender)
			defer s.Close()
			initial := &C.Metadata{NetWork: C.UDP, Host: initialHost, DstIP: netip.MustParseAddr("192.0.2.10"), DstPort: 443}
			if initialHost != "" {
				initial.DstIP = netip.Addr{}
			}
			target := initial.Clone()
			if initialHost == "fake-ip" {
				initial.Host = ""
				initial.DstIP = netip.MustParseAddr("198.18.0.1")
				target.Host = "first.invalid"
				target.DstIP = netip.Addr{}
			}
			s.AddMapping(initial, target)
			pc := &mappingPacketConn{localIP: netip.MustParseAddr("192.0.2.1")}
			for _, tc := range []struct {
				host string
				port uint16
				want string
			}{
				{"", 53, "192.0.2.10:53"},
				{"first.invalid", 443, "first.invalid:443"},
				{"first.invalid", 8443, "first.invalid:8443"},
				{"second.invalid", 4321, "192.0.2.1:4321"},
				{"first.invalid", 443, "first.invalid:443"},
			} {
				m := &C.Metadata{NetWork: C.UDP, Host: tc.host, DstPort: tc.port}
				if tc.host == "" {
					m.DstIP = netip.MustParseAddr("192.0.2.10")
				}
				packet := &domainPacket{metadata: m}
				s.processPacket(pc, packet)
				want := tc.want
				if initialHost == "" && tc.host == "first.invalid" {
					want = net.JoinHostPort("192.0.2.1", strconv.Itoa(int(tc.port)))
				}
				if pc.sent == nil || pc.sent.String() != want {
					t.Fatalf("%s:%d: sent %v, want %s", tc.host, tc.port, pc.sent, want)
				}
				if !packet.dropped {
					t.Fatal("packet was not released")
				}
				if tc.host != "" && m.DstIP.IsValid() {
					t.Fatal("original metadata was modified")
				}
			}
			wantCalls := 4
			wantDomain := "first.invalid"
			if initialHost == "" {
				wantCalls = 2 // Later packets to the same host reuse its local IP mapping.
				wantDomain = ""
			}
			if len(pc.domains) != wantCalls {
				t.Fatalf("resolve domains: %v", pc.domains)
			}
			for _, domain := range pc.domains {
				if domain != wantDomain {
					t.Fatalf("first domain changed: %v", pc.domains)
				}
			}
			other := newPacketSender().(*packetSender)
			defer other.Close()
			other.AddMapping(initial, &C.Metadata{Host: "second.invalid"})
			ctx := other.domainContext()
			if domain, _ := C.UDPRemoteDNSDomainFromContext(ctx); domain != "second.invalid" {
				t.Fatal("sessions shared domain state")
			}
		})
	}
}

func TestUDPRemoteDNSPreservesIPReplies(t *testing.T) {
	s := newPacketSender().(*packetSender)
	// Remote domain requests share the existing source session. An IP reply
	// remains an IP; do not substitute a domain or the first Fake-IP destination.
	for i, host := range []string{"one.invalid", "two.invalid"} {
		s.AddMapping(
			&C.Metadata{NetWork: C.UDP, DstIP: netip.AddrFrom4([4]byte{198, 18, 0, byte(i + 1)}), DstPort: 443},
			&C.Metadata{NetWork: C.UDP, Host: host, DstPort: 443},
		)
	}
	// IP destinations still restore their NAT mapping through the same reply path.
	s.AddMapping(
		&C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("198.18.0.3"), DstPort: 53},
		&C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("192.0.2.3"), DstPort: 53},
	)
	wants := []string{"192.0.2.1:443", "[2001:db8::1]:443", "192.0.2.2:1234", "[2001:db8::2]:1234", "198.18.0.3:53"}
	pc := &mappingPacketConn{replies: []udpReply{
		{[]byte("IPv4"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(wants[0]))},
		{[]byte("IPv6"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(wants[1]))},
		{[]byte("protocol IPv4"), M.ParseSocksaddr(wants[2])},
		{[]byte("protocol IPv6"), M.ParseSocksaddr(wants[3])},
		{[]byte("NAT"), M.ParseSocksaddr("192.0.2.3:53")},
	}}
	wb := &mappingWriteBack{}
	handleUDPToLocal(wb, pc, s, "ip-reply-test", netip.MustParseAddrPort("198.18.0.1:443"))
	if len(wb.replies) != len(wants) {
		t.Fatalf("got %d replies", len(wb.replies))
	}
	for i, want := range wants {
		if _, ok := wb.replies[i].addr.(*net.UDPAddr); !ok {
			t.Fatalf("reply is not an IP address: %T", wb.replies[i].addr)
		}
		if wb.replies[i].addr.String() != want {
			t.Fatalf("reply %d: got %s, want %s", i, wb.replies[i].addr, want)
		}
	}
	if pc.freed != len(wants) || !pc.closed {
		t.Fatal("reply resources not released")
	}
}

type noLocalDNS struct {
	resolver.Resolver
	calls int
}

func (*noLocalDNS) Invalid() bool { return true }
func (r *noLocalDNS) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	r.calls++
	return nil, errors.New("local DNS disabled")
}

type dnsRemoteProxy struct {
	C.ProxyAdapter
	enabled     bool
	destination string
}

func (*dnsRemoteProxy) Name() string                     { return "remote" }
func (*dnsRemoteProxy) Type() C.AdapterType              { return C.Socks5 }
func (p *dnsRemoteProxy) ProxyInfo() C.ProxyInfo         { return C.ProxyInfo{UDPRemoteDNS: p.enabled} }
func (*dnsRemoteProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }
func (*dnsRemoteProxy) SupportUDP() bool                 { return true }
func (p *dnsRemoteProxy) ListenPacketContext(ctx context.Context, m *C.Metadata) (C.PacketConn, error) {
	p.destination = m.UDPRemoteAddr().String()
	return &mappingPacketConn{}, nil
}
func (*mappingPacketConn) Chains() C.Chain           { return C.Chain{"remote"} }
func (*mappingPacketConn) ProviderChains() C.Chain   { return nil }
func (*mappingPacketConn) RemoteDestination() string { return "127.0.0.1" }
func (*mappingPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}
}
func (*mappingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*mappingPacketConn) SetWriteDeadline(time.Time) error { return nil }
func TestDNSDialerUDPRemoteDNS(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		r := &noLocalDNS{}
		proxy := &dnsRemoteProxy{enabled: enabled}
		d := NewDNSDialer(r, proxy, "")
		for _, packet := range []bool{false, true} {
			var conn io.Closer
			var err error
			if packet {
				conn, err = d.ListenPacket(context.Background(), "udp", "remote-only.invalid:53")
			} else {
				conn, err = d.DialContext(context.Background(), "udp", "remote-only.invalid:53")
			}
			if enabled {
				if err != nil {
					t.Fatal(err)
				}
				conn.Close()
				if proxy.destination != "remote-only.invalid:53" {
					t.Fatal("lost domain")
				}
			} else if err == nil {
				conn.Close()
				t.Fatal("default DNS path should fail without DNS")
			}
		}
		if enabled && r.calls != 0 {
			t.Fatalf("remote mode called local DNS %d times", r.calls)
		}
		if !enabled && r.calls != 2 {
			t.Fatalf("default mode DNS calls: %d", r.calls)
		}
	}
}

// A group's own option must not override the selected node's DNS policy.
type dnsRemoteGroup struct {
	C.Proxy
	leaf    C.Proxy
	enabled bool
}

func (p *dnsRemoteGroup) Unwrap(*C.Metadata, bool) C.Proxy { return p.leaf }
func (p *dnsRemoteGroup) ProxyInfo() C.ProxyInfo           { return C.ProxyInfo{UDPRemoteDNS: p.enabled} }
func TestUDPRemoteDNSSelectedNode(t *testing.T) {
	metadata := &C.Metadata{NetWork: C.UDP, Host: "remote-only.invalid", DstPort: 53}
	if udpRemoteDNS(nil, metadata) {
		t.Fatal("no proxy enabled remote DNS")
	}
	for _, enabled := range []bool{false, true} {
		leaf := &dnsRemoteGroup{enabled: enabled}
		group := &dnsRemoteGroup{enabled: !enabled, leaf: leaf}
		// Nested groups must also use the final selected node.
		outer := &dnsRemoteGroup{enabled: !enabled, leaf: group}
		if got := udpRemoteDNS(outer, metadata); got != enabled {
			t.Fatalf("selected node enabled=%v: got %v", enabled, got)
		}
	}
}
