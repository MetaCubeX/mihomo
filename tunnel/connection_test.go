package tunnel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
)

func TestRestoreReplyByDomain(t *testing.T) {
	sender := newPacketSender().(*packetSender)
	fakeIP := netip.MustParseAddr("198.18.0.8")
	sender.rememberDomain(fakeIP, "www.google.com")

	got := sender.restoreReply(M.Socksaddr{Fqdn: "www.google.com", Port: 443}, netip.AddrPort{})
	if got.Addr() != fakeIP || got.Port() != 443 {
		t.Fatalf("domain reply = %s, want 198.18.0.8:443", got)
	}
}

func TestLearnSingleReplyIP(t *testing.T) {
	sender := newPacketSender().(*packetSender)
	fakeIP := netip.MustParseAddr("198.18.0.8")
	sender.rememberDomain(fakeIP, "www.google.com")
	reply := &net.UDPAddr{IP: net.ParseIP("142.251.1.1"), Port: 443}

	got := sender.restoreReply(reply, netip.AddrPort{})
	if got.Addr() != fakeIP || got.Port() != 443 {
		t.Fatalf("first reply = %s, want 198.18.0.8:443", got)
	}
	if len(sender.unboundDomain) != 0 {
		t.Fatalf("domain still unbound: %v", sender.unboundDomain)
	}
	again := sender.restoreReply(reply, netip.AddrPort{})
	if again != got {
		t.Fatalf("second reply = %s, want %s", again, got)
	}
}

func TestDoNotBindAmbiguousReplyIP(t *testing.T) {
	sender := newPacketSender().(*packetSender)
	sender.rememberDomain(netip.MustParseAddr("198.18.0.8"), "www.google.com")
	sender.rememberDomain(netip.MustParseAddr("198.18.0.9"), "www.youtube.com")
	reply := &net.UDPAddr{IP: net.ParseIP("142.251.1.1"), Port: 443}

	got := sender.restoreReply(reply, netip.AddrPort{})
	if got.Addr().String() != "142.251.1.1" {
		t.Fatalf("ambiguous reply = %s, want the public address unchanged", got)
	}
	if len(sender.unboundDomain) != 2 {
		t.Fatalf("unbound domains = %d, want 2", len(sender.unboundDomain))
	}
}

func TestProcessPacketSkipsResolveForDomainRelay(t *testing.T) {
	sender := newPacketSender().(*packetSender)
	pc := &stubPacketConn{relay: true}
	meta := &C.Metadata{
		NetWork: C.UDP,
		Host:    "www.google.com",
		DstIP:   netip.MustParseAddr("198.18.0.8"),
		DstPort: 443,
	}
	sender.processPacket(pc, &stubPacket{meta: meta})

	if pc.resolved {
		t.Fatal("domain relay resolved the name")
	}
	socks, ok := pc.written.(M.Socksaddr)
	if !ok || socks.Fqdn != "www.google.com" || socks.Port != 443 {
		t.Fatalf("written address = %#v, want domain www.google.com:443", pc.written)
	}
	if sender.domainToOrigin["www.google.com"] != meta.DstIP {
		t.Fatalf("domain mapping = %s", sender.domainToOrigin["www.google.com"])
	}
}

func TestProcessPacketResolvesWhenDomainRelayDisabled(t *testing.T) {
	sender := newPacketSender().(*packetSender)
	pc := &stubPacketConn{}
	meta := &C.Metadata{
		NetWork: C.UDP,
		Host:    "www.google.com",
		DstPort: 443,
	}
	sender.processPacket(pc, &stubPacket{meta: meta})

	if !pc.resolved {
		t.Fatal("non-relay packet did not resolve")
	}
	udp, ok := pc.written.(*net.UDPAddr)
	if !ok || udp.IP.String() != "1.2.3.4" {
		t.Fatalf("written address = %#v, want 1.2.3.4", pc.written)
	}
}

type stubPacket struct {
	meta *C.Metadata
}

func (p *stubPacket) Data() []byte { return []byte{1} }

func (p *stubPacket) WriteBack([]byte, net.Addr) (int, error) { return 0, nil }

func (p *stubPacket) Drop() {}

func (p *stubPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9}
}

func (p *stubPacket) Metadata() *C.Metadata { return p.meta }

func (p *stubPacket) Key() string { return "k" }

type stubPacketConn struct {
	relay    bool
	resolved bool
	written  net.Addr
}

func (s *stubPacketConn) RelayUDPDomain() bool { return s.relay }

func (s *stubPacketConn) ResolveUDP(_ context.Context, metadata *C.Metadata) error {
	s.resolved = true
	metadata.DstIP = netip.MustParseAddr("1.2.3.4")
	return nil
}

func (s *stubPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	s.written = addr
	return len(b), nil
}

func (s *stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }

func (s *stubPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return nil, nil, nil, net.ErrClosed
}

func (s *stubPacketConn) Close() error                       { return nil }
func (s *stubPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (s *stubPacketConn) SetDeadline(time.Time) error        { return nil }
func (s *stubPacketConn) SetReadDeadline(time.Time) error    { return nil }
func (s *stubPacketConn) SetWriteDeadline(time.Time) error   { return nil }
func (s *stubPacketConn) Chains() C.Chain                  { return nil }
func (s *stubPacketConn) ProviderChains() C.Chain          { return nil }
func (s *stubPacketConn) AppendToChains(C.ProxyAdapter)    {}
func (s *stubPacketConn) RemoteDestination() string        { return "" }
