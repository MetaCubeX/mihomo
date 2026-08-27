package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	componentResolver "github.com/metacubex/mihomo/component/resolver"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fallbackTestClient struct {
	address  string
	started  chan struct{}
	start    sync.Once
	exchange func(context.Context, *D.Msg) (*D.Msg, error)
}

func (c *fallbackTestClient) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	c.start.Do(func() { close(c.started) })
	return c.exchange(ctx, msg)
}

func (c *fallbackTestClient) Address() string  { return c.address }
func (c *fallbackTestClient) ResetConnection() {}

func fallbackTestResponse(ip string) *D.Msg {
	msg := &D.Msg{}
	msg.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: "example.com.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip),
	}}
	return msg
}

func fallbackTestCNAMEResponse() *D.Msg {
	msg := &D.Msg{}
	msg.Answer = []D.RR{&D.CNAME{
		Hdr:    D.RR_Header{Name: "example.com.", Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 60},
		Target: "target.example.com.",
	}}
	return msg
}

func fallbackTestQuery() *D.Msg {
	return fallbackTestQueryFor("example.com.")
}

func fallbackTestQueryFor(domain string) *D.Msg {
	msg := &D.Msg{}
	msg.SetQuestion(domain, D.TypeA)
	return msg
}

func TestIPExchangeWithDelayedFallback(t *testing.T) {
	t.Run("does not start fallback when primary succeeds before delay", func(t *testing.T) {
		fallbackStarted := make(chan struct{})
		resolver := &Resolver{
			main: []dnsClient{&fallbackTestClient{
				address: "primary",
				started: make(chan struct{}),
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					return fallbackTestResponse("192.0.2.1"), nil
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: fallbackStarted,
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					return fallbackTestResponse("192.0.2.2"), nil
				},
			}},
			fallbackTimeout: 100 * time.Millisecond,
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		msg, _, err := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())

		require.NoError(t, err)
		assert.Equal(t, "192.0.2.1", msgToIP(msg)[0].String())
		select {
		case <-fallbackStarted:
			t.Fatal("fallback started before it was needed")
		default:
		}
	})

	t.Run("accepts a CNAME response without starting fallback", func(t *testing.T) {
		fallbackStarted := make(chan struct{})
		resolver := &Resolver{
			main: []dnsClient{&fallbackTestClient{
				address: "primary",
				started: make(chan struct{}),
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					return fallbackTestCNAMEResponse(), nil
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: fallbackStarted,
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					return nil, errors.New("fallback should not start")
				},
			}},
			fallbackTimeout: 100 * time.Millisecond,
		}
		query := &D.Msg{}
		query.SetQuestion("example.com.", D.TypeCNAME)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		msg, _, err := resolver.ipExchangeWithDelayedFallback(ctx, query)

		require.NoError(t, err)
		require.Len(t, msg.Answer, 1)
		_, ok := msg.Answer[0].(*D.CNAME)
		assert.True(t, ok)
		select {
		case <-fallbackStarted:
			t.Fatal("fallback started for a valid CNAME response")
		default:
		}
	})

	t.Run("starts fallback immediately when primary fails", func(t *testing.T) {
		fallbackStarted := make(chan struct{})
		resolver := &Resolver{
			main: []dnsClient{&fallbackTestClient{
				address: "primary",
				started: make(chan struct{}),
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					return nil, errors.New("primary failed")
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: fallbackStarted,
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					return fallbackTestResponse("192.0.2.2"), nil
				},
			}},
			fallbackTimeout: time.Second,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		msg, _, err := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())

		require.NoError(t, err)
		assert.Equal(t, "192.0.2.2", msgToIP(msg)[0].String())
		select {
		case <-fallbackStarted:
		default:
			t.Fatal("fallback was not started after the primary failed")
		}
	})

	t.Run("starts fallback only after the delay", func(t *testing.T) {
		fallbackStarted := make(chan struct{})
		resolver := &Resolver{
			main: []dnsClient{&fallbackTestClient{
				address: "primary",
				started: make(chan struct{}),
				exchange: func(ctx context.Context, _ *D.Msg) (*D.Msg, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: fallbackStarted,
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					return fallbackTestResponse("192.0.2.2"), nil
				},
			}},
			fallbackTimeout: 100 * time.Millisecond,
		}

		type exchangeResult struct {
			msg *D.Msg
			err error
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resultCh := make(chan exchangeResult, 1)
		go func() {
			msg, _, err := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())
			resultCh <- exchangeResult{msg: msg, err: err}
		}()

		select {
		case <-fallbackStarted:
			t.Fatal("fallback started before the configured delay")
		case <-time.After(30 * time.Millisecond):
		}

		select {
		case <-fallbackStarted:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("fallback did not start after the configured delay")
		}

		res := <-resultCh
		require.NoError(t, res.err)
		assert.Equal(t, "192.0.2.2", msgToIP(res.msg)[0].String())
	})

	t.Run("uses the first valid response after fallback starts", func(t *testing.T) {
		primaryRelease := make(chan struct{})
		fallbackRelease := make(chan struct{})
		fallbackStarted := make(chan struct{})
		resolver := &Resolver{
			main: []dnsClient{&fallbackTestClient{
				address: "primary",
				started: make(chan struct{}),
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					<-primaryRelease
					return fallbackTestResponse("192.0.2.1"), nil
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: fallbackStarted,
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					<-fallbackRelease
					return fallbackTestResponse("192.0.2.2"), nil
				},
			}},
			fallbackTimeout: 10 * time.Millisecond,
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resultCh := make(chan *D.Msg, 1)
		go func() {
			msg, _, _ := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())
			resultCh <- msg
		}()

		select {
		case <-fallbackStarted:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("fallback did not start")
		}
		close(primaryRelease)
		msg := <-resultCh
		assert.Equal(t, "192.0.2.1", msgToIP(msg)[0].String())
		close(fallbackRelease)
	})
}

func TestNewFailureUsesRootProbeForScopeClassification(t *testing.T) {
	t.Run("healthy root probe isolates only the failed query", func(t *testing.T) {
		var exampleQueries atomic.Int32
		probeFinished := make(chan struct{})
		var probeOnce sync.Once
		resolver := &Resolver{
			main: []dnsClient{&fallbackTestClient{
				address: "primary",
				started: make(chan struct{}),
				exchange: func(ctx context.Context, query *D.Msg) (*D.Msg, error) {
					switch query.Question[0].Name {
					case ".":
						response := &D.Msg{}
						response.SetReply(query)
						probeOnce.Do(func() { close(probeFinished) })
						return response, nil
					case "example.com.":
						exampleQueries.Add(1)
						<-ctx.Done()
						return nil, ctx.Err()
					default:
						return fallbackTestResponse("192.0.2.1"), nil
					}
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: make(chan struct{}),
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					return fallbackTestResponse("192.0.2.2"), nil
				},
			}},
			fallbackTimeout: 10 * time.Millisecond,
			delayedFallback: true,
			fallbackCircuit: newFallbackCircuit(time.Minute),
			fallbackLabel:   "test-nameserver",
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		msg, _, err := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.2", msgToIP(msg)[0].String())
		select {
		case <-probeFinished:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("root classification probe did not finish")
		}
		scope, _ := resolver.fallbackState(fallbackTestQuery(), false)
		assert.Equal(t, fallbackScopeDomain, scope)

		msg, _, err = resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQueryFor("other.example."))
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.1", msgToIP(msg)[0].String())
		msg, _, err = resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.2", msgToIP(msg)[0].String())
		assert.Equal(t, int32(1), exampleQueries.Load())
	})

	t.Run("failed root probe opens the group circuit", func(t *testing.T) {
		var rootQueries atomic.Int32
		resolver := &Resolver{
			main: []dnsClient{&fallbackTestClient{
				address: "primary",
				started: make(chan struct{}),
				exchange: func(ctx context.Context, query *D.Msg) (*D.Msg, error) {
					if query.Question[0].Name == "." {
						rootQueries.Add(1)
					}
					<-ctx.Done()
					return nil, ctx.Err()
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: make(chan struct{}),
				exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
					return fallbackTestResponse("192.0.2.2"), nil
				},
			}},
			fallbackTimeout: 10 * time.Millisecond,
			delayedFallback: true,
			fallbackCircuit: newFallbackCircuit(40 * time.Millisecond),
			fallbackLabel:   "test-nameserver",
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		msg, _, err := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.2", msgToIP(msg)[0].String())
		require.Eventually(t, func() bool {
			scope, _ := resolver.fallbackState(fallbackTestQueryFor("other.example."), false)
			return scope == fallbackScopeGroup
		}, 500*time.Millisecond, 5*time.Millisecond)

		msg, _, err = resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQueryFor("other.example."))
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.2", msgToIP(msg)[0].String())
		assert.Equal(t, int32(1), rootQueries.Load())

		time.Sleep(50 * time.Millisecond)
		msg, _, err = resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQueryFor("third.example."))
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.2", msgToIP(msg)[0].String())
		assert.Equal(t, int32(1), rootQueries.Load(), "recovery must not run another root probe")
	})
}

func TestRootProbeIsSingleTaskAndStaleResultIsIgnored(t *testing.T) {
	rootStarted := make(chan struct{})
	rootRelease := make(chan struct{})
	var rootOnce sync.Once
	var rootQueries atomic.Int32
	resolver := &Resolver{
		main: []dnsClient{&fallbackTestClient{
			address: "primary",
			started: make(chan struct{}),
			exchange: func(_ context.Context, query *D.Msg) (*D.Msg, error) {
				if query.Question[0].Name == "." {
					rootQueries.Add(1)
					rootOnce.Do(func() { close(rootStarted) })
					<-rootRelease
					return nil, errors.New("root probe failed")
				}
				return nil, errors.New("primary failed")
			},
		}},
		fallbackTimeout: 100 * time.Millisecond,
		fallbackCircuit: newFallbackCircuit(time.Minute),
		fallbackLabel:   "test-nameserver",
	}

	first := fallbackTestQueryFor("first.example.")
	second := fallbackTestQueryFor("second.example.")
	resolver.classifyNewFailure(first)
	select {
	case <-rootStarted:
	case <-time.After(time.Second):
		t.Fatal("root probe did not start")
	}
	resolver.classifyNewFailure(second)
	assert.Equal(t, int32(1), rootQueries.Load(), "concurrent failures must share one probe task")

	resolver.recoverFallback(fallbackScopeDomain, first)
	close(rootRelease)
	require.Never(t, func() bool {
		scope, _ := resolver.fallbackState(fallbackTestQueryFor("unrelated.example."), false)
		return scope == fallbackScopeGroup
	}, 100*time.Millisecond, 2*time.Millisecond, "a stale failed probe must not open the group circuit")
}

func TestRecoveryRaceUsesFastestAnswerAndLatePrimaryCanRecover(t *testing.T) {
	mainRelease := make(chan struct{})
	var rootQueries atomic.Int32
	resolver := &Resolver{
		main: []dnsClient{&fallbackTestClient{
			address: "primary",
			started: make(chan struct{}),
			exchange: func(ctx context.Context, query *D.Msg) (*D.Msg, error) {
				if query.Question[0].Name == "." {
					rootQueries.Add(1)
				}
				select {
				case <-mainRelease:
					return fallbackTestResponse("192.0.2.1"), nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		}},
		fallback: []dnsClient{&fallbackTestClient{
			address: "fallback",
			started: make(chan struct{}),
			exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
				return fallbackTestResponse("192.0.2.2"), nil
			},
		}},
		fallbackTimeout: 200 * time.Millisecond,
		delayedFallback: true,
		fallbackCircuit: newFallbackCircuit(20 * time.Millisecond),
		fallbackLabel:   "test-nameserver",
	}
	resolver.openDomainFallback(fallbackTestQuery())
	time.Sleep(25 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	msg, _, err := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.2", msgToIP(msg)[0].String())
	close(mainRelease)
	require.Eventually(t, func() bool {
		scope, _ := resolver.fallbackState(fallbackTestQuery(), false)
		return scope == fallbackScopeNone
	}, 500*time.Millisecond, 5*time.Millisecond)
	assert.Equal(t, int32(0), rootQueries.Load(), "recovery must use the original query, not a root probe")
}

func TestFallbackCircuitSeparatesAAndAAAAQueries(t *testing.T) {
	resolver := &Resolver{
		fallbackCircuit: newFallbackCircuit(time.Minute),
		fallbackLabel:   "test-nameserver",
	}
	aQuery := fallbackTestQuery()
	aaaaQuery := &D.Msg{}
	aaaaQuery.SetQuestion("EXAMPLE.COM.", D.TypeAAAA)

	resolver.openDomainFallback(aQuery)
	aScope, _ := resolver.fallbackState(aQuery, false)
	aaaaScope, _ := resolver.fallbackState(aaaaQuery, false)
	assert.Equal(t, fallbackScopeDomain, aScope)
	assert.Equal(t, fallbackScopeNone, aaaaScope)
}

func TestNewResolverConfiguresDirectAndProxyFallback(t *testing.T) {
	config := Config{
		ProxyServer:      []NameServer{{Addr: "192.0.2.1:53"}},
		ProxyFallback:    []NameServer{{Net: "system"}},
		DirectServer:     []NameServer{{Addr: "192.0.2.2:53"}},
		DirectFallback:   []NameServer{{Net: "system"}},
		RecoveryInterval: 300000,
	}

	resolvers := NewResolver(config)
	require.NotNil(t, resolvers.ProxyResolver)
	assert.True(t, resolvers.ProxyResolver.delayedFallback)
	assert.Equal(t, componentResolver.DefaultDNSTimeout, resolvers.ProxyResolver.fallbackQueryTimeout())
	require.NotNil(t, resolvers.ProxyResolver.fallbackCircuit)
	assert.Equal(t, 5*time.Minute, resolvers.ProxyResolver.fallbackCircuit.interval)

	require.NotNil(t, resolvers.DirectResolver)
	assert.True(t, resolvers.DirectResolver.delayedFallback)
	assert.Equal(t, componentResolver.DefaultDNSTimeout, resolvers.DirectResolver.fallbackQueryTimeout())
	require.NotNil(t, resolvers.DirectResolver.fallbackCircuit)
	assert.Equal(t, 5*time.Minute, resolvers.DirectResolver.fallbackCircuit.interval)

	disabled := NewResolver(Config{
		DirectServer:   []NameServer{{Addr: "192.0.2.2:53"}},
		DirectFallback: []NameServer{{Net: "system"}},
	})
	require.NotNil(t, disabled.DirectResolver)
	assert.Nil(t, disabled.DirectResolver.fallbackCircuit)
}

func TestFallbackCircuitDoesNotCacheFallbackOnlyResponses(t *testing.T) {
	var fallbackQueries atomic.Int32
	resolver := &Resolver{
		main: []dnsClient{&fallbackTestClient{
			address: "primary",
			started: make(chan struct{}),
			exchange: func(ctx context.Context, _ *D.Msg) (*D.Msg, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}},
		fallback: []dnsClient{&fallbackTestClient{
			address: "fallback",
			started: make(chan struct{}),
			exchange: func(context.Context, *D.Msg) (*D.Msg, error) {
				fallbackQueries.Add(1)
				return fallbackTestResponse("192.0.2.2"), nil
			},
		}},
		fallbackTimeout: 5 * time.Millisecond,
		delayedFallback: true,
		fallbackCircuit: newFallbackCircuit(time.Minute),
		fallbackLabel:   "test-nameserver",
		cache:           Config{}.newCache(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		msg, err := resolver.ExchangeContext(ctx, fallbackTestQuery())
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.2", msgToIP(msg)[0].String())
	}
	assert.Equal(t, int32(2), fallbackQueries.Load())
}

func TestFallbackStateTransitionsPreserveUnrelatedCache(t *testing.T) {
	resolver := &Resolver{
		fallbackCircuit: newFallbackCircuit(time.Minute),
		fallbackLabel:   "test-nameserver",
		cache:           Config{}.newCache(),
	}
	cachedQuery := fallbackTestQueryFor("cached.example.")
	putMsgToCache(resolver.cache, cachedQuery.Question[0], fallbackTestResponse("192.0.2.10"))
	assertCached := func() {
		_, _, hit := getMsgFromCache(resolver.cache, cachedQuery.Question[0])
		assert.True(t, hit)
	}

	failedQuery := fallbackTestQueryFor("failed.example.")
	resolver.openDomainFallback(failedQuery)
	assertCached()
	resolver.recoverFallback(fallbackScopeDomain, failedQuery)
	assertCached()

	resolver.fallbackCircuit.mu.Lock()
	resolver.fallbackCircuit.probeRunning = true
	resolver.fallbackCircuit.probeGeneration++
	generation := resolver.fallbackCircuit.probeGeneration
	resolver.fallbackCircuit.mu.Unlock()
	resolver.finishRootProbe(generation, true)
	assertCached()
}
