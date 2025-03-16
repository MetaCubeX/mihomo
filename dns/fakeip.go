package dns

import (
	stdCtx "context"
	"strings"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	D "github.com/miekg/dns"
)

type fakeIPclient struct {
	back dnsClient
}

var _ dnsClient = &fakeIPclient{}

func newFakeIPClient(back dnsClient) *fakeIPclient {
	return &fakeIPclient{back: back}
}

func (f *fakeIPclient) ExchangeContext(ctx stdCtx.Context, r *D.Msg) (*D.Msg, error) {
	q := r.Question[0]
	host := strings.TrimRight(q.Name, ".")

	// todo unify
	switch q.Qtype {
	case D.TypeAAAA, D.TypeSVCB, D.TypeHTTPS:
		return handleMsgWithEmptyAnswer(r), nil
	}

	if q.Qtype != D.TypeA {
		return f.back.ExchangeContext(ctx, r)
	}

	fakeip := resolver.DefaultHostMapper.(*ResolverEnhancer).fakePool

	msg := fakeipExchange(q, fakeip, host, r)
	return msg, nil
}

func fakeipExchange(q D.Question, fakePool *fakeip.Pool, host string, r *D.Msg) *D.Msg {
	rr := &D.A{}
	rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: dnsDefaultTTL}
	ip := fakePool.Lookup(host)
	rr.A = ip.AsSlice()
	msg := r.Copy()
	msg.Answer = []D.RR{rr}

	setMsgTTL(msg, 1)
	msg.SetRcode(r, D.RcodeSuccess)
	msg.Authoritative = true
	msg.RecursionAvailable = true
	return msg
}

func (r fakeIPclient) Address() string {
	return "fakeip://" + r.back.Address()
}

func (r fakeIPclient) ResetConnection() {}
