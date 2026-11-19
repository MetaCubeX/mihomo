package adapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"

	"github.com/stretchr/testify/require"
)

// slowServer writes 64 KiB chunks every 10ms for up to 2 seconds
func slowServer(t *testing.T) *httptest.Server {
	chunk := make([]byte, 64*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 200; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSpeedTestLimits(t *testing.T) {
	srv := slowServer(t)
	proxy := NewProxy(outbound.NewDirect())

	start := time.Now()
	speed, err := proxy.SpeedTest(context.Background(), srv.URL, 100<<20, 500*time.Millisecond)
	require.NoError(t, err)
	require.Less(t, time.Since(start), 2*time.Second, "duration limit")
	require.InDelta(t, 6.4e6, float64(speed), 4e6) // ~64 KiB per 10ms

	h, ok := proxy.LastSpeedForTestUrl(srv.URL)
	require.True(t, ok)
	require.Equal(t, speed, h.Speed)

	start = time.Now()
	speed, err = proxy.SpeedTest(context.Background(), srv.URL, 256*1024, 5*time.Second)
	require.NoError(t, err)
	require.NotZero(t, speed)
	require.Less(t, time.Since(start), time.Second, "byte limit")
}

func TestSpeedTestFailureRecorded(t *testing.T) {
	proxy := NewProxy(outbound.NewDirect())
	speed, err := proxy.SpeedTest(context.Background(), "http://127.0.0.1:1/", 1024, time.Second)
	require.Error(t, err)
	require.Zero(t, speed)
	h, ok := proxy.LastSpeedForTestUrl("http://127.0.0.1:1/")
	require.True(t, ok)
	require.Zero(t, h.Speed)
}

func TestSpeedTestSerialAndCoalesced(t *testing.T) {
	var mu sync.Mutex
	var arrivals []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrivals = append(arrivals, time.Now())
		mu.Unlock()
		chunk := make([]byte, 64*1024)
		for i := 0; i < 200; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer srv.Close()

	const duration = 200 * time.Millisecond
	proxies := []*Proxy{NewProxy(outbound.NewDirect()), NewProxy(outbound.NewDirect()), NewProxy(outbound.NewDirect())}
	var wg sync.WaitGroup
	// three callers test every proxy at the same time
	for i := 0; i < 3; i++ {
		for _, p := range proxies {
			wg.Add(1)
			go func(p *Proxy) {
				defer wg.Done()
				speed, err := p.SpeedTest(context.Background(), srv.URL, 100<<20, duration)
				require.NoError(t, err)
				require.NotZero(t, speed)
			}(p)
		}
	}
	wg.Wait()

	require.Len(t, arrivals, len(proxies), "waiting callers reuse the result of the same proxy")
	for i := 1; i < len(arrivals); i++ {
		require.GreaterOrEqual(t, arrivals[i].Sub(arrivals[i-1]), duration, "speed tests must not run concurrently")
	}
}
