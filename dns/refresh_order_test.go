package dns

import (
	"context"
	"errors"
	"fmt"
	D "github.com/miekg/dns"
	"sync"
	"testing"
	"time"
)

// Done is evaluated after flight admission. The optional gate lets the result
// become ready before the select sees an already-canceled context.
type refreshAdmissionContext struct {
	context.Context
	once     sync.Once
	admitted chan struct{}
	gate     <-chan struct{}
}

func (c *refreshAdmissionContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.admitted) })
	if c.gate != nil {
		<-c.gate
	}
	return c.Context.Done()
}

type refreshResult struct {
	message *D.Msg
	err     error
}

func waitRefreshResult(t *testing.T, ch <-chan refreshResult) refreshResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(time.Second):
		t.Fatal("exchange did not finish")
		return refreshResult{}
	}
}
func waitRefreshAdmission(t *testing.T, c *refreshAdmissionContext) {
	t.Helper()
	select {
	case <-c.admitted:
	case <-time.After(time.Second):
		t.Fatal("exchange did not join flight")
	}
}

func TestRefreshCancellationOrder(t *testing.T) {
	for _, canceled := range []int{0, 1} {
		t.Run(fmt.Sprint(canceled), func(t *testing.T) {
			gate := make(chan struct{})
			var release sync.Once
			defer release.Do(func() { close(gate) })
			client := &refreshClient{entered: make(chan struct{}, 4), release: gate}
			r := NewResolverFromClient(client)
			requests := [2]*D.Msg{refreshQuestion("order.invalid."), refreshQuestion("order.invalid.")}
			var contexts [2]*refreshAdmissionContext
			var cancel [2]context.CancelFunc
			var done [2]chan refreshResult
			for i := range contexts {
				ctx, stop := context.WithCancel(context.Background())
				defer stop()
				cancel[i] = stop
				contexts[i] = &refreshAdmissionContext{Context: ctx, admitted: make(chan struct{})}
				done[i] = make(chan refreshResult, 1)
				go func(i int) { m, e := r.ExchangeContext(contexts[i], requests[i]); done[i] <- refreshResult{m, e} }(i)
				waitRefreshAdmission(t, contexts[i])
			}
			cancel[canceled]()
			if got := waitRefreshResult(t, done[canceled]); !errors.Is(got.err, context.Canceled) {
				t.Fatal(got.err)
			}
			requests[canceled].Question[0].Name = "mutated.invalid."
			release.Do(func() { close(gate) })
			got := waitRefreshResult(t, done[1-canceled])
			if got.err != nil || got.message.Question[0].Name != "order.invalid." {
				t.Fatal("remaining waiter lost owned response", got.err)
			}
			waitRefresh(t, r)
			if client.calls.Load() != 1 {
				t.Fatal("cancellation duplicated upstream", client.calls.Load())
			}
		})
	}
}
func TestRefreshSharedResponsesDoNotAlias(t *testing.T) {
	gate := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	client := &refreshClient{entered: make(chan struct{}, 4), release: gate}
	r := NewResolverFromClient(client)
	done := [2]chan refreshResult{make(chan refreshResult, 1), make(chan refreshResult, 1)}
	for i := range done {
		ctx := &refreshAdmissionContext{Context: context.Background(), admitted: make(chan struct{})}
		go func(i int) {
			m, e := r.ExchangeContext(ctx, refreshQuestion("shared.invalid."))
			done[i] <- refreshResult{m, e}
		}(i)
		waitRefreshAdmission(t, ctx)
	}
	release.Do(func() { close(gate) })
	a, b := waitRefreshResult(t, done[0]), waitRefreshResult(t, done[1])
	if a.err != nil || b.err != nil {
		t.Fatal(a.err, b.err)
	}
	a.message.Question[0].Name = "mutated.invalid."
	a.message.Answer[0].Header().Ttl = 1
	if b.message.Question[0].Name != "shared.invalid." || b.message.Answer[0].Header().Ttl != 60 {
		t.Fatal("waiter responses alias")
	}
	cached, _, hit := r.cache.GetWithExpire(refreshQuestion("shared.invalid.").Question[0].String())
	if !hit || cached.Answer[0].Header().Ttl != 60 {
		t.Fatal("response aliases cache")
	}
}
func TestRefreshPrefersReadyResultToCancellation(t *testing.T) {
	upstream, choose := make(chan struct{}), make(chan struct{})
	var release, unblock sync.Once
	defer release.Do(func() { close(upstream) })
	defer unblock.Do(func() { close(choose) })
	client := &refreshClient{entered: make(chan struct{}, 4), release: upstream}
	r := NewResolverFromClient(client)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &refreshAdmissionContext{Context: base, admitted: make(chan struct{}), gate: choose}
	done := make(chan refreshResult, 1)
	request := refreshQuestion("ready.invalid.")
	go func() { m, e := r.ExchangeContext(ctx, request); done <- refreshResult{m, e} }()
	waitRefreshAdmission(t, ctx)
	joined, owner := r.group.DoChanWithOwner(request.Question[0].String(), func() (*D.Msg, error) { t.Error("joiner ran"); return nil, nil })
	if owner {
		t.Fatal("owner missing")
	}
	release.Do(func() { close(upstream) })
	select {
	case result := <-joined:
		if result.Err != nil {
			t.Fatal(result.Err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream result missing")
	}
	cancel()
	unblock.Do(func() { close(choose) })
	if got := waitRefreshResult(t, done); got.err != nil || got.message == nil {
		t.Fatal("ready result discarded", got.err)
	}
}
func TestRefreshImmediateCompletionAndReadmission(t *testing.T) {
	gate := make(chan struct{})
	close(gate)
	client := &refreshClient{entered: make(chan struct{}, 128), release: gate}
	r := NewResolverFromClient(client)
	request := refreshQuestion("reenter.invalid.")
	r.refresh(request)
	waitRefresh(t, r)
	for i := 0; i < 100; i++ {
		r.refresh(request)
	}
	waitRefresh(t, r)
	if client.calls.Load() != 1 {
		t.Fatal("fresh result refreshed", client.calls.Load())
	}
	r.cache.SetWithExpire(request.Question[0].String(), refreshResponse(request, 60), time.Now().Add(-time.Second))
	r.refresh(request)
	waitRefresh(t, r)
	if client.calls.Load() != 2 {
		t.Fatal("expired key did not reenter", client.calls.Load())
	}
	for i := 0; i < 100; i++ {
		r.refresh(refreshQuestion(fmt.Sprintf("distinct%d.invalid.", i)))
	}
	waitRefresh(t, r)
	if client.calls.Load() != 102 {
		t.Fatal("distinct keys merged", client.calls.Load())
	}
}

func TestRefreshDistinctCanceledKeysSettle(t *testing.T) {
	gate := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	client := &refreshClient{entered: make(chan struct{}, 128), release: gate}
	r := NewResolverFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 100; i++ {
		if _, err := r.ExchangeContext(ctx, refreshQuestion(fmt.Sprintf("cancel%d.invalid.", i))); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for client.calls.Load() < 100 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if client.calls.Load() != 100 {
		t.Fatal("distinct canceled keys lost", client.calls.Load())
	}
	release.Do(func() { close(gate) })
	waitRefresh(t, r)
	for i := 0; i < 100; i++ {
		if _, _, hit := r.cache.GetWithExpire(refreshQuestion(fmt.Sprintf("cancel%d.invalid.", i)).Question[0].String()); !hit {
			t.Fatal("background result not cached", i)
		}
	}
}

func TestRefreshCanceledSoleOwnerKeepsRetry(t *testing.T) {
	gate := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	client := &refreshClient{entered: make(chan struct{}, 4), release: gate, fail: true}
	r := NewResolverFromClient(client)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &refreshAdmissionContext{Context: base, admitted: make(chan struct{})}
	done := make(chan refreshResult, 1)
	// Bypass the outer refresh wrapper, which would itself join the flight and
	// make Shared true. This targets the sole-owner cancellation monitor.
	go func() {
		m, e := r.exchangeWithoutCache(ctx, refreshQuestion("sole.invalid."))
		done <- refreshResult{m, e}
	}()
	waitRefreshAdmission(t, ctx)
	cancel()
	if result := waitRefreshResult(t, done); !errors.Is(result.err, context.Canceled) {
		t.Fatal(result.err)
	}
	release.Do(func() { close(gate) })
	deadline := time.Now().Add(time.Second)
	for client.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if client.calls.Load() != 2 {
		t.Fatal("canceled sole owner did not preserve one retry", client.calls.Load())
	}
}
