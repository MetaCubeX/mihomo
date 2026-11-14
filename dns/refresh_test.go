package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type refreshClient struct {
	calls    atomic.Int64
	entered  chan struct{}
	release  <-chan struct{}
	observed chan string
	fail     bool
}

func (c *refreshClient) Address() string  { return "resource.invalid" }
func (c *refreshClient) ResetConnection() {}
func (c *refreshClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	c.calls.Add(1)
	select {
	case c.entered <- struct{}{}:
	default:
	}
	select {
	case <-c.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if c.observed != nil {
		c.observed <- m.Question[0].Name
	}
	if c.fail {
		return nil, errors.New("synthetic failure")
	}
	return refreshResponse(m, 60), nil
}
func waitRefresh(t testing.TB, r *Resolver) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r.refreshMu.Lock()
		active := len(r.refreshing)
		r.refreshMu.Unlock()
		if active == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("refresh ownership did not settle")
}
func TestRefreshOwnsRequestAndDeduplicates(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			gate := make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(gate) }) }
			defer release()
			client := &refreshClient{entered: make(chan struct{}, 4), release: gate, observed: make(chan string, 4)}
			r := NewResolverFromClient(client)
			m := refreshQuestion("owned.invalid.")
			ctx := context.Background()
			if cancelled {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			} else {
				r.cache.SetWithExpire(m.Question[0].String(), refreshResponse(m, 60), time.Now().Add(-time.Second))
			}
			for i := 0; i < 1000; i++ {
				_, err := r.ExchangeContext(ctx, m)
				if cancelled && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if !cancelled && err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-client.entered:
			case <-time.After(time.Second):
				t.Fatal("upstream not started")
			}
			r.refreshMu.Lock()
			owners := len(r.refreshing)
			r.refreshMu.Unlock()
			if owners != 1 || client.calls.Load() != 1 {
				t.Fatal("duplicate refresh", owners, client.calls.Load())
			}
			// Mutating after the API returns must not race the still-running exchange.
			m.Question[0].Name = "mutated.invalid."
			release()
			waitRefresh(t, r)
			select {
			case name := <-client.observed:
				if name != "owned.invalid." {
					t.Fatal("request retained caller storage", name)
				}
			case <-time.After(time.Second):
				t.Fatal("missing observed question")
			}
		})
	}
}
func TestRefreshSkipsFreshCacheBeforeSpawn(t *testing.T) {
	gate := make(chan struct{})
	close(gate)
	client := &refreshClient{entered: make(chan struct{}, 1), release: gate}
	r := NewResolverFromClient(client)
	m := refreshQuestion("fresh.invalid.")
	r.cache.SetWithExpire(m.Question[0].String(), refreshResponse(m, 60), time.Now().Add(time.Minute))
	for i := 0; i < 100; i++ {
		r.refresh(m)
	}
	if client.calls.Load() != 0 || len(r.refreshing) != 0 {
		t.Fatal("fresh cache launched refresh")
	}
}
func TestSingleFailureRetriesOnlyOnce(t *testing.T) {
	gate := make(chan struct{})
	close(gate)
	client := &refreshClient{entered: make(chan struct{}, 4), release: gate, fail: true}
	r := NewResolverFromClient(client)
	if _, err := r.ExchangeContext(context.Background(), refreshQuestion("failure.invalid.")); err == nil {
		t.Fatal("failure lost")
	}
	deadline := time.Now().Add(time.Second)
	for client.calls.Load() < 2 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	time.Sleep(20 * time.Millisecond)
	if calls := client.calls.Load(); calls != 2 {
		t.Fatal("retry envelope changed", calls)
	}
}

func TestStaleFailureRetryEnvelope(t *testing.T) {
	gate := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(gate) })
	client := &refreshClient{entered: make(chan struct{}, 4), release: gate, fail: true}
	r := NewResolverFromClient(client)
	m := refreshQuestion("stale-failure.invalid.")
	r.cache.SetWithExpire(m.Question[0].String(), refreshResponse(m, 60), time.Now().Add(-time.Second))
	for i := 0; i < 1000; i++ {
		if _, err := r.ExchangeContext(context.Background(), m); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-client.entered:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	once.Do(func() { close(gate) })
	waitRefresh(t, r)
	deadline := time.Now().Add(time.Second)
	for client.calls.Load() < 2 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	time.Sleep(20 * time.Millisecond)
	if calls := client.calls.Load(); calls != 2 {
		t.Fatal("stale dedup retry exceeded one extra attempt", calls)
	}
}

func TestSharedFailureDoesNotAcquireRetry(t *testing.T) {
	gate := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(gate) })
	client := &refreshClient{entered: make(chan struct{}, 4), release: gate, fail: true}
	r := NewResolverFromClient(client)
	m := refreshQuestion("shared-failure.invalid.")
	done := make(chan error, 1)
	go func() { _, err := r.ExchangeContext(context.Background(), m); done <- err }()
	select {
	case <-client.entered:
	case <-time.After(time.Second):
		t.Fatal("foreground did not start")
	}
	// Join the actual resolver flight synchronously to make Shared deterministic.
	joined, owner := r.group.DoChanWithOwner(m.Question[0].String(), func() (*D.Msg, error) { t.Error("joiner executed"); return nil, nil })
	if owner {
		t.Fatal("held foreground flight missing")
	}
	once.Do(func() { close(gate) })
	if err := <-done; err == nil {
		t.Fatal("foreground failure lost")
	}
	if result := <-joined; result.Err == nil || !result.Shared {
		t.Fatal("shared error contract changed", result)
	}
	time.Sleep(20 * time.Millisecond)
	if calls := client.calls.Load(); calls != 1 {
		t.Fatal("shared error incorrectly retried", calls)
	}
}

func refreshQuestion(name string) *D.Msg { m := new(D.Msg); m.SetQuestion(name, D.TypeA); return m }
func refreshResponse(m *D.Msg, ttl uint32) *D.Msg {
	response := new(D.Msg)
	response.SetReply(m)
	response.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: ttl}, A: net.IPv4(198, 18, 0, 1)}}
	return response
}
