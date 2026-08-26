package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fallbackTestClient struct {
	address  string
	started  chan struct{}
	start    sync.Once
	exchange func(context.Context) (*D.Msg, error)
}

func (c *fallbackTestClient) ExchangeContext(ctx context.Context, _ *D.Msg) (*D.Msg, error) {
	c.start.Do(func() { close(c.started) })
	return c.exchange(ctx)
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

func fallbackTestQuery() *D.Msg {
	msg := &D.Msg{}
	msg.SetQuestion("example.com.", D.TypeA)
	return msg
}

func TestIPExchangeWithDelayedFallback(t *testing.T) {
	t.Run("does not start fallback when primary succeeds before delay", func(t *testing.T) {
		fallbackStarted := make(chan struct{})
		resolver := &Resolver{
			main: []dnsClient{&fallbackTestClient{
				address: "primary",
				started: make(chan struct{}),
				exchange: func(context.Context) (*D.Msg, error) {
					return fallbackTestResponse("192.0.2.1"), nil
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: fallbackStarted,
				exchange: func(context.Context) (*D.Msg, error) {
					return fallbackTestResponse("192.0.2.2"), nil
				},
			}},
			fallbackDelay: 100 * time.Millisecond,
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		msg, err := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())

		require.NoError(t, err)
		assert.Equal(t, "192.0.2.1", msgToIP(msg)[0].String())
		select {
		case <-fallbackStarted:
			t.Fatal("fallback started before it was needed")
		default:
		}
	})

	t.Run("starts fallback immediately when primary fails", func(t *testing.T) {
		fallbackStarted := make(chan struct{})
		resolver := &Resolver{
			main: []dnsClient{&fallbackTestClient{
				address: "primary",
				started: make(chan struct{}),
				exchange: func(context.Context) (*D.Msg, error) {
					return nil, errors.New("primary failed")
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: fallbackStarted,
				exchange: func(context.Context) (*D.Msg, error) {
					return fallbackTestResponse("192.0.2.2"), nil
				},
			}},
			fallbackDelay: time.Second,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		msg, err := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())

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
				exchange: func(ctx context.Context) (*D.Msg, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: fallbackStarted,
				exchange: func(context.Context) (*D.Msg, error) {
					return fallbackTestResponse("192.0.2.2"), nil
				},
			}},
			fallbackDelay: 100 * time.Millisecond,
		}

		type exchangeResult struct {
			msg *D.Msg
			err error
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resultCh := make(chan exchangeResult, 1)
		go func() {
			msg, err := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())
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
				exchange: func(context.Context) (*D.Msg, error) {
					<-primaryRelease
					return fallbackTestResponse("192.0.2.1"), nil
				},
			}},
			fallback: []dnsClient{&fallbackTestClient{
				address: "fallback",
				started: fallbackStarted,
				exchange: func(context.Context) (*D.Msg, error) {
					<-fallbackRelease
					return fallbackTestResponse("192.0.2.2"), nil
				},
			}},
			fallbackDelay: 10 * time.Millisecond,
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resultCh := make(chan *D.Msg, 1)
		go func() {
			msg, _ := resolver.ipExchangeWithDelayedFallback(ctx, fallbackTestQuery())
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
