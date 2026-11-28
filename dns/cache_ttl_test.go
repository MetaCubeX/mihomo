package dns

import (
	D "github.com/miekg/dns"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestCacheInsertionTTL(t *testing.T) {
	for _, scenario := range []string{"empty", "zero-answer", "zero-additional", "opt-in-answer", "opt-in-authority", "zero-authority", "mixed", "opt-only", "negative-soa", "servfail", "acme", "max-ttl"} {
		t.Run(scenario, func(t *testing.T) {
			m := cacheQuestion("cache.invalid.")
			msg := cacheResponse(m, 60)
			want := uint32(60)
			opt := &D.OPT{Hdr: D.RR_Header{Name: ".", Rrtype: D.TypeOPT, Ttl: 0}}
			switch scenario {
			case "empty":
				msg.Answer = nil
				want = 0
			case "zero-answer":
				msg.Answer[0].Header().Ttl = 0
				want = 0
			case "zero-additional":
				msg.Extra = []D.RR{&D.A{Hdr: D.RR_Header{Name: "extra.invalid.", Rrtype: D.TypeA, Ttl: 0}, A: net.IPv4(198, 18, 0, 3)}}
				want = 0
			case "opt-in-answer":
				msg.Answer = append(msg.Answer, opt)
				want = 0 // Only Extra OPT was excluded by the existing helper.
			case "opt-in-authority":
				msg.Ns = []D.RR{opt}
				want = 0
			case "zero-authority":
				msg.Ns = []D.RR{&D.NS{Hdr: D.RR_Header{Name: "cache.invalid.", Rrtype: D.TypeNS, Ttl: 0}, Ns: "ns.invalid."}}
				want = 0
			case "mixed":
				msg.Extra = []D.RR{opt, &D.A{Hdr: D.RR_Header{Name: "ns.invalid.", Rrtype: D.TypeA, Ttl: 30}, A: net.IPv4(198, 18, 0, 2)}}
				want = 30
			case "opt-only":
				msg.Answer = nil
				msg.Extra = []D.RR{opt}
				want = 0
			case "negative-soa":
				msg.Answer = nil
				msg.Rcode = D.RcodeNameError
				msg.Ns = []D.RR{&D.SOA{Hdr: D.RR_Header{Name: "invalid.", Rrtype: D.TypeSOA, Ttl: 15}, Ns: "ns.invalid.", Mbox: "hostmaster.invalid.", Minttl: 5}}
				want = 15
			case "servfail":
				msg.Answer = nil
				msg.Rcode = D.RcodeServerFailure
				msg.Extra = []D.RR{opt}
				want = 5
			case "acme":
				m.SetQuestion("_acme-challenge.cache.invalid.", D.TypeTXT)
				want = 0
			case "max-ttl":
				msg.Answer[0].Header().Ttl = ^uint32(0)
				want = ^uint32(0)
			}
			before := msg.Copy()
			cache := Config{}.newCache()
			start := time.Now()
			putMsgToCache(cache, m.Question[0], msg)
			// Msg.Copy normalizes nil slices; normalize both snapshots equally.
			if !reflect.DeepEqual(before, msg.Copy()) {
				t.Fatal("input mutated")
			}
			cached, expire, hit := cache.GetWithExpire(m.Question[0].String())
			if want == 0 {
				if hit {
					t.Fatal("uncacheable response stored")
				}
				return
			}
			if !hit || cached == nil {
				t.Fatal("cacheable response lost")
			}
			// The existing LRU stores expiry in Unix seconds. Compare in that
			// precision, bounded by the insertion call, rather than requiring
			// the cache to preserve the input timestamp's subsecond component.
			if got, min, max := expire.Unix(), start.Unix()+int64(want), time.Now().Unix()+int64(want); got < min || got > max {
				t.Fatal("TTL changed", got, min, max)
			}
			for _, rr := range cached.Extra {
				if rr.Header().Rrtype == D.TypeOPT {
					t.Fatal("OPT cached")
				}
			}
			if len(cached.Answer) > 0 {
				cached.Answer[0].Header().Ttl = 99
				if msg.Answer[0].Header().Ttl == 99 {
					t.Fatal("cached RR aliases input")
				}
			}
		})
	}
}

func cacheQuestion(name string) *D.Msg { m := new(D.Msg); m.SetQuestion(name, D.TypeA); return m }
func cacheResponse(m *D.Msg, ttl uint32) *D.Msg {
	response := new(D.Msg)
	response.SetReply(m)
	response.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: ttl}, A: net.IPv4(198, 18, 0, 1)}}
	return response
}

func BenchmarkCacheInsertion(b *testing.B) {
	for _, ttl := range []uint32{0, 60} {
		name := "zero-ttl"
		if ttl != 0 {
			name = "cacheable"
		}
		b.Run(name, func(b *testing.B) {
			request := cacheQuestion("bench.invalid.")
			response := cacheResponse(request, ttl)
			cache := Config{}.newCache()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				putMsgToCache(cache, request.Question[0], response)
			}
		})
	}
}

func TestUncacheableResponseDoesNotAllocate(t *testing.T) {
	request := cacheQuestion("zero.invalid.")
	response := cacheResponse(request, 0)
	cache := Config{}.newCache()
	if allocations := testing.AllocsPerRun(100, func() { putMsgToCache(cache, request.Question[0], response) }); allocations != 0 {
		t.Fatal("uncacheable response allocated", allocations)
	}
}
