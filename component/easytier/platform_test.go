package easytier

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"

	"github.com/easytier/easytier/easytier-go/platform"
	D "github.com/miekg/dns"
)

type testDNSResolver struct {
	resolver.Resolver
	exchange func(context.Context, *D.Msg) (*D.Msg, error)
}

func (*testDNSResolver) Invalid() bool { return true }

func (r *testDNSResolver) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	return r.exchange(ctx, m)
}

func TestDNSRecordsUseMihomoResolver(t *testing.T) {
	oldProxy, oldDefault := resolver.ProxyServerHostResolver, net.DefaultResolver
	t.Cleanup(func() {
		resolver.ProxyServerHostResolver = oldProxy
		net.DefaultResolver = oldDefault
	})
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("net.DefaultResolver was used")
			return nil, errors.New("forbidden resolver")
		},
	}
	resolver.ProxyServerHostResolver = &testDNSResolver{exchange: func(_ context.Context, m *D.Msg) (*D.Msg, error) {
		reply := new(D.Msg).SetReply(m)
		switch m.Question[0].Qtype {
		case D.TypeTXT:
			reply.Answer = []D.RR{&D.TXT{Txt: []string{"ok"}}}
		case D.TypeSRV:
			reply.Answer = []D.RR{&D.SRV{Target: "peer.example.", Port: 11010}}
		}
		return reply, nil
	}}

	txt, err := (DNSResolver{}).LookupTXT(context.Background(), platform.DNSQuery{Host: "example"})
	if err != nil || txt != "ok" {
		t.Fatalf("TXT: %q %v", txt, err)
	}
	srv, err := (DNSResolver{}).LookupSRV(context.Background(), platform.DNSQuery{Host: "example"})
	if err != nil || len(srv) != 1 || srv[0].Target != "peer.example." || srv[0].Port != 11010 {
		t.Fatalf("SRV: %v %v", srv, err)
	}
}

func TestUDPBindPreservesWildcardPort(t *testing.T) {
	_, address := udpBind(platform.UDPBindOptions{LocalAddr: &net.UDPAddr{Port: 45678}})
	_, port, err := net.SplitHostPort(address)
	if err != nil || port != "45678" {
		t.Fatalf("%s: %v", address, err)
	}
}

type forbiddenDialer struct{}

func (forbiddenDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	panic("unexpected proxy session")
}

func (forbiddenDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	panic("unexpected proxy socket")
}

func TestListenTCPInternalAllowedThroughProxyDialer(t *testing.T) {
	factory := SocketFactory{Dialer: forbiddenDialer{}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := factory.ListenTCP(ctx, platform.TCPListenOptions{
		Bind:    platform.TCPBindOptions{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}},
		Purpose: platform.TCPListenProxyNAT,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := factory.ListenTCP(ctx, platform.TCPListenOptions{
		Bind:    platform.TCPBindOptions{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}},
		Purpose: platform.TCPListenDirect,
	}); err == nil {
		t.Fatal("external listener through proxy must fail")
	}
}
