package adapter

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
)

// speedTestSem allows only one speed test at a time process-wide,
// concurrent downloads would share the uplink and distort each other.
var speedTestSem = make(chan struct{}, 1)

// SpeedTest downloads url through the proxy until maxBytes are read or duration
// has elapsed since the response started, and returns the speed in bytes per second.
// Dialing and waiting for the response are bounded by ctx and not counted.
// If another caller finished a test of the same url while this one was waiting
// for its turn, that result is returned instead of downloading again.
// implements C.Proxy
func (p *Proxy) SpeedTest(ctx context.Context, url string, maxBytes int64, duration time.Duration) (speed uint64, err error) {
	queued := time.Now()
	select {
	case speedTestSem <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-speedTestSem }()

	if h, ok := p.speeds.Load(url); ok && h.Time.After(queued) {
		return h.Speed, nil
	}

	speed, err = p.speedTest(ctx, url, maxBytes, duration)
	p.speeds.Store(url, C.SpeedHistory{Time: time.Now(), Speed: speed})
	return
}

func (p *Proxy) speedTest(ctx context.Context, url string, maxBytes int64, duration time.Duration) (uint64, error) {
	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return 0, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			var metadata C.Metadata
			if err := metadata.SetRemoteAddress(address); err != nil {
				return nil, err
			}
			return p.DialContext(ctx, &metadata)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   true,
	}
	defer transport.CloseIdleConnections()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	start := time.Now()
	timer := time.AfterFunc(duration, cancel)
	defer timer.Stop()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBytes))
	elapsed := time.Since(start)
	if n == 0 || elapsed <= 0 {
		return 0, err
	}
	// reaching the byte limit or the duration is a normal end of the test
	return uint64(float64(n) / elapsed.Seconds()), nil
}

// LastSpeedForTestUrl returns the latest speed test result of url
// implements C.Proxy
func (p *Proxy) LastSpeedForTestUrl(url string) (C.SpeedHistory, bool) {
	return p.speeds.Load(url)
}

// SpeedHistories returns the latest speed test result of each tested url
func (p *Proxy) SpeedHistories() map[string]C.SpeedHistory {
	histories := map[string]C.SpeedHistory{}
	p.speeds.Range(func(url string, h C.SpeedHistory) bool {
		histories[url] = h
		return true
	})
	return histories
}
