package easytier

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
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
