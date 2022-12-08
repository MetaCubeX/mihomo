package provider

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Dreamacro/clash/common/atomic"
	"github.com/Dreamacro/clash/common/batch"
	"github.com/Dreamacro/clash/common/singledo"
	"github.com/Dreamacro/clash/common/utils"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	"github.com/dlclark/regexp2"
)

const (
	defaultURLTestTimeout = time.Second * 5
	defaultURLTestURL     = "https://www.gstatic.com/generate_204"
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type extraOption struct {
	expectedStatus utils.IntRanges[uint16]
	filters        map[string]struct{}
}

type HealthCheck struct {
	url            string
	extra          map[string]*extraOption
	mu             sync.Mutex
	started        *atomic.Bool
	proxies        []C.Proxy
	interval       uint
	lazy           bool
	expectedStatus utils.IntRanges[uint16]
	lastTouch      *atomic.Int64
	done           chan struct{}
	singleDo       *singledo.Single[struct{}]
}

func (hc *HealthCheck) process() {
	if hc.started.Load() {
		log.Warnln("Skip start health check timer due to it's started")
		return
	}

	ticker := time.NewTicker(time.Duration(hc.interval) * time.Second)
	hc.start()
	for {
		select {
		case <-ticker.C:
			now := time.Now().Unix()
			if !hc.lazy || now-hc.lastTouch.Load() < int64(hc.interval) {
				hc.check()
			} else {
				log.Debugln("Skip once health check because we are lazy")
			}
		case <-hc.done:
			ticker.Stop()
			hc.stop()
			return
		}
	}
}

func (hc *HealthCheck) setProxy(proxies []C.Proxy) {
	hc.proxies = proxies
}

func (hc *HealthCheck) registerHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	url = strings.TrimSpace(url)
	if len(url) == 0 || url == hc.url {
		log.Debugln("ignore invalid health check url: %s", url)
		return
	}

	hc.mu.Lock()
	defer hc.mu.Unlock()

	// if the provider has not set up health checks, then modify it to be the same as the group's interval
	if hc.interval == 0 {
		hc.interval = interval
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

	// due to the time-consuming nature of health checks, a maximum of defaultMaxTestURLNum URLs can be set for testing
	if len(hc.extra) > C.DefaultMaxHealthCheckUrlNum {
		log.Debugln("skip add url: %s to health check because it has reached the maximum limit: %d", url, C.DefaultMaxHealthCheckUrlNum)
		return
	}

	option := &extraOption{filters: map[string]struct{}{}, expectedStatus: expectedStatus}
	splitAndAddFiltersToExtra(filter, option)
	hc.extra[url] = option

	if hc.auto() && !hc.started.Load() {
		go hc.process()
	}
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
	hc.lastTouch.Store(time.Now().Unix())
}

func (hc *HealthCheck) start() {
	hc.started.Store(true)
}

func (hc *HealthCheck) stop() {
	hc.started.Store(false)
}

func (hc *HealthCheck) check() {

	if len(hc.proxies) == 0 {
		return
	}

	_, _, _ = hc.singleDo.Do(func() (struct{}, error) {
		id := utils.NewUUIDV4().String()
		log.Debugln("Start New Health Checking {%s}", id)
		b, _ := batch.New[bool](context.Background(), batch.WithConcurrencyNum[bool](10))

		// execute default health check
		option := &extraOption{filters: nil, expectedStatus: hc.expectedStatus}
		hc.execute(b, hc.url, id, option)

		// execute extra health check
		if len(hc.extra) != 0 {
			for url, option := range hc.extra {
				hc.execute(b, url, id, option)
			}
		}
		b.Wait()
		log.Debugln("Finish A Health Checking {%s}", id)
		return struct{}{}, nil
	})
}

func (hc *HealthCheck) execute(b *batch.Batch[bool], url, uid string, option *extraOption) {
	url = strings.TrimSpace(url)
	if len(url) == 0 {
		log.Debugln("Health Check has been skipped due to testUrl is empty, {%s}", uid)
		return
	}

	var filterReg *regexp2.Regexp
	var store = C.OriginalHistory
	var expectedStatus utils.IntRanges[uint16]
	if option != nil {
		if url != hc.url {
			store = C.ExtraHistory
		}

		expectedStatus = option.expectedStatus
		if len(option.filters) != 0 {
			filters := make([]string, 0, len(option.filters))
			for filter := range option.filters {
				filters = append(filters, filter)
			}

			filterReg = regexp2.MustCompile(strings.Join(filters, "|"), 0)
		}
	}

	for _, proxy := range hc.proxies {
		// skip proxies that do not require health check
		if filterReg != nil {
			if match, _ := filterReg.FindStringMatch(proxy.Name()); match == nil {
				continue
			}
		}

		p := proxy
		b.Go(p.Name(), func() (bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
			defer cancel()
			log.Debugln("Health Checking, proxy: %s, url: %s, id: {%s}", p.Name(), url, uid)
			_, _ = p.URLTest(ctx, url, expectedStatus, store)
			log.Debugln("Health Checked, proxy: %s, url: %s, alive: %t, delay: %d ms uid: {%s}", p.Name(), url, p.AliveForTestUrl(url), p.LastDelayForTestUrl(url), uid)
			return false, nil
		})
	}
}

func (hc *HealthCheck) close() {
	hc.done <- struct{}{}
}

func NewHealthCheck(proxies []C.Proxy, url string, interval uint, lazy bool, expectedStatus utils.IntRanges[uint16]) *HealthCheck {
	if len(url) == 0 {
		interval = 0
		expectedStatus = nil
		url = defaultURLTestURL
	}

	return &HealthCheck{
		proxies:        proxies,
		url:            url,
		extra:          map[string]*extraOption{},
		started:        atomic.NewBool(false),
		interval:       interval,
		lazy:           lazy,
		expectedStatus: expectedStatus,
		lastTouch:      atomic.NewInt64(0),
		done:           make(chan struct{}, 1),
		singleDo:       singledo.NewSingle[struct{}](time.Second),
	}
}
