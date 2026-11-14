package dns

import (
	"context"
	"fmt"
	D "github.com/miekg/dns"
	"net"
	"strings"
	"testing"
)

type refreshBenchClient struct{}

func (refreshBenchClient) Address() string  { return "bench.invalid" }
func (refreshBenchClient) ResetConnection() {}
func (refreshBenchClient) ExchangeContext(_ context.Context, m *D.Msg) (*D.Msg, error) {
	response := new(D.Msg)
	response.SetReply(m)
	response.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(198, 18, 0, 1)}}
	return response, nil
}

// Includes foreground ownership cost rather than reporting only stale-hit wins.
func BenchmarkRefreshMiss(b *testing.B) {
	for _, extra := range []bool{false, true} {
		b.Run(fmt.Sprint(extra), func(b *testing.B) {
			r := NewResolverFromClient(refreshBenchClient{})
			m := new(D.Msg)
			m.SetQuestion("miss.invalid.", D.TypeA)
			if extra {
				m.Extra = []D.RR{&D.TXT{Hdr: D.RR_Header{Name: "meta.invalid.", Rrtype: D.TypeTXT, Class: D.ClassINET}, Txt: []string{strings.Repeat("x", 128), strings.Repeat("y", 128), strings.Repeat("z", 128), strings.Repeat("w", 128)}}}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.cache.Clear()
				if _, err := r.ExchangeContext(context.Background(), m); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
