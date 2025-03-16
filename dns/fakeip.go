package dns

import (
	stdCtx "context"
	"strings"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/context"
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
	fakeip := resolver.DefaultHostMapper.(*ResolverEnhancer).fakePool

	dnsCtx := context.NewDNSContext(ctx, r)
	return fakeipExchange(dnsCtx, r, &fakeipExchangeOption{
		fakePool:    fakeip,
		forceFakeip: true,
		back: func(ctx *context.DNSContext, r *D.Msg) (*D.Msg, error) {
			return f.back.ExchangeContext(ctx.Context, r)
		},
	})
}

type fakeipExchangeOption struct {
	fakePool    *fakeip.Pool
	forceFakeip bool
	back        handler
}

func fakeipExchange(ctx *context.DNSContext, r *D.Msg, option *fakeipExchangeOption) (*D.Msg, error) {
	q := r.Question[0]
	host := strings.TrimRight(q.Name, ".")

	fakePool := option.fakePool
	back := option.back
	if !option.forceFakeip {
		if fakePool.ShouldSkipped(host) {
			return back(ctx, r)
		}
	}

	switch q.Qtype {
	case D.TypeAAAA, D.TypeSVCB, D.TypeHTTPS:
		return handleMsgWithEmptyAnswer(r), nil
	}

	if q.Qtype != D.TypeA {
		return back(ctx, r)
	}

	ctx.SetType(context.DNSTypeFakeIP)

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
	return msg, nil
}

func (r fakeIPclient) Address() string {
	return "fakeip://" + r.back.Address()
}

func (r fakeIPclient) ResetConnection() {}
