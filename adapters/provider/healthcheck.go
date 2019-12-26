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

type HealthCheck struct {
	url      string
	proxies  []C.Proxy
	interval uint
	done     chan struct{}
}

func (hc *HealthCheck) process() {
	ticker := time.NewTicker(time.Duration(hc.interval) * time.Second)

	go hc.check()
	for {
		select {
		case <-ticker.C:
			hc.check()
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

func (hc *HealthCheck) check() {
	ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
	for _, proxy := range hc.proxies {
		go proxy.URLTest(ctx, hc.url)
	}

	<-ctx.Done()
	cancel()
}

func (hc *HealthCheck) close() {
	hc.done <- struct{}{}
}

func NewHealthCheck(proxies []C.Proxy, url string, interval uint) *HealthCheck {
	return &HealthCheck{
		proxies:  proxies,
		url:      url,
		interval: interval,
		done:     make(chan struct{}, 1),
	}
}
