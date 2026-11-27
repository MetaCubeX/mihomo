package dns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

// A lookup that starts while the old network is dying is stuck on a server that can never
// answer (the Wi-Fi router once Wi-Fi is gone). After the network-change reset, which Clash
// Meta for Android runs on every network change (NotifyDnsChanged -> FlushCacheWithDefaultResolver
// -> ClearCache + ResetConnection), a new request for the same name must start a fresh lookup
// on the new network instead of waiting out the stuck one.
func TestResetConnectionStartsFreshLookup(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	var answering atomic.Bool // false = old network (queries lost), true = new network
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if !answering.Load() {
				continue
			}
			req := new(D.Msg)
			if req.Unpack(buf[:n]) != nil || len(req.Question) == 0 {
				continue
			}
			resp := new(D.Msg)
			resp.SetReply(req)
			if req.Question[0].Qtype == D.TypeA {
				resp.Answer = append(resp.Answer, &D.A{
					Hdr: D.RR_Header{Name: req.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 1),
				})
			}
			out, _ := resp.Pack()
			_, _ = pc.WriteTo(out, addr)
		}
	}()

	r := NewResolver(Config{Main: []NameServer{{Net: "udp", Addr: pc.LocalAddr().String()}}})
	q := new(D.Msg)
	q.SetQuestion("claude.example.", D.TypeA)

	go func() { // the request that is in flight while Wi-Fi dies
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = r.ExchangeContext(ctx, q.Copy())
	}()
	time.Sleep(300 * time.Millisecond)

	answering.Store(true) // the new network is up
	r.ClearCache()        // what CMFA does on the network change
	r.ResetConnection()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg, err := r.ExchangeContext(ctx, q.Copy())
	took := time.Since(start)
	if err != nil || msg == nil || len(msg.Answer) == 0 {
		t.Fatalf("request after the network change failed after %v (it waited for the stuck lookup): %v", took.Round(time.Millisecond), err)
	}
	if took > time.Second {
		t.Fatalf("request after the network change took %v", took.Round(time.Millisecond))
	}
	t.Logf("request after the network change answered in %v", took.Round(time.Millisecond))
}
