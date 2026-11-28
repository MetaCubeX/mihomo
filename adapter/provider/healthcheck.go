package provider

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/sync/errgroup"
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type extraOption struct {
	option  C.HealthCheckOption
	filters map[string]struct{}
}

type HealthCheck struct {
	ctx       context.Context
	ctxCancel context.CancelFunc
	url       string
	extra     map[string]*extraOption
	mu        sync.Mutex
	proxies   []C.Proxy
	interval  time.Duration
	lazy      bool
	option    C.HealthCheckOption
	lastTouch atomic.TypedValue[time.Time]
	singleDo  *singledo.Single[struct{}]
	timeout   time.Duration
}

func (hc *HealthCheck) process() {
	ticker := time.NewTicker(hc.interval)
	go hc.check()
	for {
		select {
		case <-ticker.C:
			lastTouch := hc.lastTouch.Load()
			since := time.Since(lastTouch)
			if !hc.lazy || since < hc.interval {
				hc.check()
			} else {
				log.Debugln("Skip once health check because we are lazy")
			}
		case <-hc.ctx.Done():
			ticker.Stop()
			return
		}
	}
}

func (hc *HealthCheck) setProxies(proxies []C.Proxy) {
	hc.proxies = proxies
}

func (hc *HealthCheck) registerHealthCheckTask(url string, option C.HealthCheckOption, filter string, interval uint) {
	url = strings.TrimSpace(url)
	if len(url) == 0 || url == hc.url {
		log.Debugln("ignore invalid health check url: %s", url)
		return
	}

	hc.mu.Lock()
	defer hc.mu.Unlock()

	// if the provider has not set up health checks, then modify it to be the same as the group's interval
	if hc.interval == 0 {
		hc.interval = time.Duration(interval) * time.Second
	}

	if hc.extra == nil {
		hc.extra = make(map[string]*extraOption)
	}

	// prioritize the use of previously registered configurations, especially those from provider
	if _, ok := hc.extra[url]; ok {
		// provider default health check does not set filter
		if url != hc.url && len(filter) != 0 {
			splitAndAddFiltersToExtra(filter, hc.extra[url])
		}

		log.Debugln("health check url: %s exists", url)
		return
	}

	extra := &extraOption{filters: map[string]struct{}{}, option: option.WithDefault()}
	splitAndAddFiltersToExtra(filter, extra)
	hc.extra[url] = extra
}

func splitAndAddFiltersToExtra(filter string, option *extraOption) {
	filter = strings.TrimSpace(filter)
	if len(filter) != 0 {
		for _, regex := range strings.Split(filter, "`") {
			regex = strings.TrimSpace(regex)
			if len(regex) != 0 {
				option.filters[regex] = struct{}{}
			}
		}
	}
}

func (hc *HealthCheck) auto() bool {
	return hc.interval != 0
}

func (hc *HealthCheck) touch() {
	hc.lastTouch.Store(time.Now())
}

func (hc *HealthCheck) check() {
	if len(hc.proxies) == 0 {
		return
	}

	_, _, _ = hc.singleDo.Do(func() (struct{}, error) {
		id := utils.NewUUIDV4().String()
		log.Debugln("Start New Health Checking {%s}", id)
		b := new(errgroup.Group)
		b.SetLimit(10)

		// execute default health check
		option := &extraOption{filters: nil, option: hc.option}
		hc.execute(b, hc.url, id, option)

		// execute extra health check
		if len(hc.extra) != 0 {
			for url, option := range hc.extra {
				hc.execute(b, url, id, option)
			}
		}
		_ = b.Wait()
		log.Debugln("Finish A Health Checking {%s}", id)
		return struct{}{}, nil
	})
}

func (hc *HealthCheck) execute(b *errgroup.Group, url, uid string, option *extraOption) {
	url = strings.TrimSpace(url)
	if len(url) == 0 {
		log.Debugln("Health Check has been skipped due to testUrl is empty, {%s}", uid)
		return
	}

	var filterReg *regexp2.Regexp
	healthCheckOption := C.HealthCheckOption{}.WithDefault()
	if option != nil {
		healthCheckOption = option.option.WithDefault()
		if len(option.filters) != 0 {
			filters := make([]string, 0, len(option.filters))
			for filter := range option.filters {
				filters = append(filters, filter)
			}

			filterReg = regexp2.MustCompile(strings.Join(filters, "|"), regexp2.None)
		}
	}

	for _, proxy := range hc.proxies {
		// skip proxies that do not require health check
		if filterReg != nil {
			if match, _ := filterReg.MatchString(proxy.Name()); !match {
				continue
			}
		}

		p := proxy
		b.Go(func() error {
			ctx, cancel := context.WithTimeout(hc.ctx, hc.timeout)
			defer cancel()
			log.Debugln("Health Checking, proxy: %s, url: %s, id: {%s}", p.Name(), url, uid)
			_, _ = p.URLTest(ctx, url, healthCheckOption.ExpectedStatus, healthCheckOption)
			log.Debugln("Health Checked, proxy: %s, url: %s, alive: %t, delay: %d ms uid: {%s}", p.Name(), url, p.AliveForTestUrl(url), p.LastDelayForTestUrl(url), uid)
			return nil
		})
	}
}

func (hc *HealthCheck) close() {
	hc.ctxCancel()
}

func NewHealthCheck(proxies []C.Proxy, url string, timeout uint, interval uint, lazy bool, expectedStatus utils.IntRanges[uint16]) *HealthCheck {
	return NewHealthCheckWithOption(proxies, url, timeout, interval, lazy, C.HealthCheckOption{ExpectedStatus: expectedStatus})
}

func NewHealthCheckWithOption(proxies []C.Proxy, url string, timeout uint, interval uint, lazy bool, option C.HealthCheckOption) *HealthCheck {
	if url == "" {
		option.ExpectedStatus = nil
		interval = 0
	}
	if timeout == 0 {
		timeout = 5000
	}
	option = option.WithDefault()
	ctx, cancel := context.WithCancel(context.Background())

	return &HealthCheck{
		ctx:       ctx,
		ctxCancel: cancel,
		proxies:   proxies,
		url:       url,
		timeout:   time.Duration(timeout) * time.Millisecond,
		extra:     map[string]*extraOption{},
		interval:  time.Duration(interval) * time.Second,
		lazy:      lazy,
		option:    option,
		singleDo:  singledo.NewSingle[struct{}](time.Second),
	}
}
