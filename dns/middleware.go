package dns

import (
	"net"
	"strings"

	"github.com/Dreamacro/clash/component/fakeip"
	"github.com/Dreamacro/clash/component/trie"
	"github.com/Dreamacro/clash/log"

	D "github.com/miekg/dns"
)

type handler func(w D.ResponseWriter, r *D.Msg)
type middleware func(next handler) handler

func withHosts(hosts *trie.DomainTrie) middleware {
	return func(next handler) handler {
		return func(w D.ResponseWriter, r *D.Msg) {
			q := r.Question[0]

			if !isIPRequest(q) {
				next(w, r)
				return
			}

			record := hosts.Search(strings.TrimRight(q.Name, "."))
			if record == nil {
				next(w, r)
				return
			}

			ip := record.Data.(net.IP)
			msg := r.Copy()

			if v4 := ip.To4(); v4 != nil && q.Qtype == D.TypeA {
				rr := &D.A{}
				rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: dnsDefaultTTL}
				rr.A = v4

				msg.Answer = []D.RR{rr}
			} else if v6 := ip.To16(); v6 != nil && q.Qtype == D.TypeAAAA {
				rr := &D.AAAA{}
				rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: dnsDefaultTTL}
				rr.AAAA = v6

				msg.Answer = []D.RR{rr}
			} else {
				next(w, r)
				return
			}

			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true

			w.WriteMsg(msg)
			return
		}
	}
}

func withFakeIP(fakePool *fakeip.Pool) middleware {
	return func(next handler) handler {
		return func(w D.ResponseWriter, r *D.Msg) {
			q := r.Question[0]

			if q.Qtype == D.TypeAAAA {
				msg := &D.Msg{}
				msg.Answer = []D.RR{}

				msg.SetRcode(r, D.RcodeSuccess)
				msg.Authoritative = true
				msg.RecursionAvailable = true

				w.WriteMsg(msg)
				return
			} else if q.Qtype != D.TypeA {
				next(w, r)
				return
			}

			host := strings.TrimRight(q.Name, ".")
			if fakePool.LookupHost(host) {
				next(w, r)
				return
			}

			rr := &D.A{}
			rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: dnsDefaultTTL}
			ip := fakePool.Lookup(host)
			rr.A = ip
			msg := r.Copy()
			msg.Answer = []D.RR{rr}

			setMsgTTL(msg, 1)
			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true

			w.WriteMsg(msg)
			return
		}
	}
}

func withResolver(resolver *Resolver) handler {
	return func(w D.ResponseWriter, r *D.Msg) {
		q := r.Question[0]

		// return a empty AAAA msg when ipv6 disabled
		if !resolver.ipv6 && q.Qtype == D.TypeAAAA {
			msg := &D.Msg{}
			msg.Answer = []D.RR{}

			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true

			w.WriteMsg(msg)
			return
		}

		msg, err := resolver.Exchange(r)
		if err != nil {
			log.Debugln("[DNS Server] Exchange %s failed: %v", q.String(), err)
			D.HandleFailed(w, r)
			return
		}
		msg.SetRcode(r, msg.Rcode)
		msg.Authoritative = true
		w.WriteMsg(msg)
		return
	}
}

func compose(middlewares []middleware, endpoint handler) handler {
	length := len(middlewares)
	h := endpoint
	for i := length - 1; i >= 0; i-- {
		middleware := middlewares[i]
		h = middleware(h)
	}

	return h
}

func newHandler(resolver *Resolver) handler {
	middlewares := []middleware{}

	if resolver.hosts != nil {
		middlewares = append(middlewares, withHosts(resolver.hosts))
	}

	if resolver.FakeIPEnabled() {
		middlewares = append(middlewares, withFakeIP(resolver.pool))
	}

	return compose(middlewares, withResolver(resolver))
}
