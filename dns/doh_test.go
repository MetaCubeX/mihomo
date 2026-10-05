package dns

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A DoH server that accepts TCP and never answers must not keep the dials
// alive after the queries that started them have given up. Each open
// server-side connection below is one in-flight client dial.
func TestDoHDialEndsAfterQueryGivesUp(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var open atomic.Int32
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			open.Add(1)
			go func() {
				defer open.Add(-1)
				_, _ = io.Copy(io.Discard, conn) // returns once the client closes the dial
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})

	doh := newDoHClient("https://"+ln.Addr().String()+"/dns-query", nil, false,
		map[string]string{"skip-cert-verify": "true"}, nil, "").(*dnsOverHTTPS)
	t.Cleanup(func() { _ = doh.Close() })

	// A steady stream of queries, each giving up after a short timeout, so
	// that the client is reset while other queries are still dialing.
	const queries = 20
	var wg sync.WaitGroup
	for i := 0; i < queries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			m := new(D.Msg)
			m.SetQuestion("example.com.", D.TypeA)
			_, err := doh.ExchangeContext(ctx, m)
			assert.Error(t, err)
		}()
		time.Sleep(20 * time.Millisecond)
	}
	wg.Wait()
	require.Positive(t, open.Load(), "no dial reached the server")

	deadline := time.Now().Add(dialTimeout + 5*time.Second)
	for open.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	require.Zero(t, open.Load(), "dials still open %s after their queries gave up", dialTimeout+5*time.Second)
}
