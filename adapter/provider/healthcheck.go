package provider

import (
	"context"
	"time"

	"github.com/Dreamacro/clash/common/batch"
	C "github.com/Dreamacro/clash/constant"

	"go.uber.org/atomic"
)

const (
	defaultURLTestTimeout = time.Second * 5
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type HealthCheck struct {
	url       string
	proxies   []C.Proxy
	interval  uint
	lazy      bool
	lastTouch *atomic.Int64
	done      chan struct{}
}

func (hc *HealthCheck) process() {
	ticker := time.NewTicker(time.Duration(hc.interval) * time.Second)

	go hc.check()
	for {
		select {
		case <-ticker.C:
			now := time.Now().Unix()
			if !hc.lazy || now-hc.lastTouch.Load() < int64(hc.interval) {
				hc.check()
			}
		case <-hc.done:
			ticker.Stop()
			return
		}
	}
}

func (hc *HealthCheck) setProxy(proxies []C.Proxy) {
	hc.proxies = proxies
}

func (hc *HealthCheck) auto() bool {
	return hc.interval != 0
}

func (hc *HealthCheck) touch() {
	hc.lastTouch.Store(time.Now().Unix())
}

func (hc *HealthCheck) check() {
	b, _ := batch.New(context.Background(), batch.WithConcurrencyNum(10))
	for _, proxy := range hc.proxies {
		p := proxy
		b.Go(p.Name(), func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
			defer cancel()
			p.URLTest(ctx, hc.url)
			return nil, nil
		})
	}
	b.Wait()
}

func (hc *HealthCheck) close() {
	hc.done <- struct{}{}
}

func NewHealthCheck(proxies []C.Proxy, url string, interval uint, lazy bool) *HealthCheck {
	return &HealthCheck{
		proxies:   proxies,
		url:       url,
		interval:  interval,
		lazy:      lazy,
		lastTouch: atomic.NewInt64(0),
		done:      make(chan struct{}, 1),
	}
}
