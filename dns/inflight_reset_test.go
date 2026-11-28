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
			out, _ := answerA(req).Pack()
			_, _ = pc.WriteTo(out, addr)
		}
	}()

	r := NewResolver(Config{Main: []NameServer{{Net: "udp", Addr: pc.LocalAddr().String()}}})
	q := new(D.Msg)
	q.SetQuestion("claude.example.", D.TypeA)

	go exchangeInBackground(r.Resolver, q) // the request that is in flight while Wi-Fi dies
	time.Sleep(300 * time.Millisecond)

	answering.Store(true) // the new network is up
	r.ClearCache()        // what CMFA does on the network change
	r.ResetConnection()

	expectFreshAnswer(t, r.Resolver, q, "request after the network change")
}

// While a client's reset is still blocked (DoH's ResetConnection waits for clientMu, which
// getClient holds while it builds a transport), a new request must already be able to start a
// fresh lookup and be answered by a client that works on the new network.
func TestResetConnectionFreshLookupWhileClientResetBlocks(t *testing.T) {
	doh := &fakeClient{resetBlock: make(chan struct{}), usableAfterReset: true}
	defer close(doh.resetBlock)
	system := &fakeClient{} // UDP to the system resolver: nothing to reset, works once the new DNS is set
	r := &Resolver{main: []dnsClient{doh, system}, cache: Config{}.newCache()}
	q := new(D.Msg)
	q.SetQuestion("claude.example.", D.TypeA)

	go exchangeInBackground(r, q) // in flight on the old network
	time.Sleep(100 * time.Millisecond)

	system.usable.Store(true) // UpdateSystemDNS: the new network's resolver
	go r.ResetConnection()    // blocks inside doh.ResetConnection
	time.Sleep(50 * time.Millisecond)

	expectFreshAnswer(t, r, q, "request while a client reset is blocked")
}

// A lookup that starts while the clients are still being reset can go out on a connection
// from before the change and hang. Requests made after ResetConnection returns must not join it.
func TestResetConnectionForgetsLookupsStartedDuringReset(t *testing.T) {
	doh := &fakeClient{resetBlock: make(chan struct{}), usableAfterReset: true}
	r := &Resolver{main: []dnsClient{doh}, cache: Config{}.newCache()}
	q := new(D.Msg)
	q.SetQuestion("claude.example.", D.TypeA)

	go exchangeInBackground(r, q) // in flight on the old network
	time.Sleep(100 * time.Millisecond)

	resetDone := make(chan struct{})
	go func() { r.ResetConnection(); close(resetDone) }()
	time.Sleep(50 * time.Millisecond)

	go exchangeInBackground(r, q) // starts while doh is still being reset, on its old connection
	time.Sleep(50 * time.Millisecond)

	close(doh.resetBlock)
	<-resetDone

	expectFreshAnswer(t, r, q, "request after ResetConnection returned")
}

// fakeClient is one upstream across a network change. A query that starts before the client
// is usable hangs until its context ends, like a query on the old network.
type fakeClient struct {
	usable           atomic.Bool
	resetBlock       chan struct{} // if set, ResetConnection blocks until it is closed
	usableAfterReset bool          // ResetConnection reconnects on the new network
}

func (c *fakeClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	if !c.usable.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return answerA(m), nil
}

func (c *fakeClient) Address() string { return "fake" }

func (c *fakeClient) ResetConnection() {
	if c.resetBlock != nil {
		<-c.resetBlock
	}
	if c.usableAfterReset {
		c.usable.Store(true)
	}
}

func answerA(req *D.Msg) *D.Msg {
	resp := new(D.Msg)
	resp.SetReply(req)
	if req.Question[0].Qtype == D.TypeA {
		resp.Answer = append(resp.Answer, &D.A{
			Hdr: D.RR_Header{Name: req.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		})
	}
	return resp
}

func exchangeInBackground(r *Resolver, q *D.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = r.ExchangeContext(ctx, q.Copy())
}

func expectFreshAnswer(t *testing.T, r *Resolver, q *D.Msg, what string) {
	t.Helper()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg, err := r.ExchangeContext(ctx, q.Copy())
	took := time.Since(start)
	if err != nil || msg == nil || len(msg.Answer) == 0 {
		t.Fatalf("%s failed after %v (it waited for a stuck lookup): %v", what, took.Round(time.Millisecond), err)
	}
	if took > time.Second {
		t.Fatalf("%s took %v", what, took.Round(time.Millisecond))
	}
	t.Logf("%s answered in %v", what, took.Round(time.Millisecond))
}
