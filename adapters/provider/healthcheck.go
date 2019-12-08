package provider

import (
	"context"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

const (
	defaultURLTestTimeout = time.Second * 5
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type healthCheck struct {
	url     string
	proxies []C.Proxy
	ticker  *time.Ticker
}

func (hc *healthCheck) process() {
	go hc.check()
	for range hc.ticker.C {
		hc.check()
	}
}

func (hc *healthCheck) check() {
	ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
	for _, proxy := range hc.proxies {
		go proxy.URLTest(ctx, hc.url)
	}

	<-ctx.Done()
	cancel()
}

func (hc *healthCheck) close() {
	hc.ticker.Stop()
}

func newHealthCheck(proxies []C.Proxy, url string, interval uint) *healthCheck {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	return &healthCheck{
		proxies: proxies,
		url:     url,
		ticker:  ticker,
	}
}
