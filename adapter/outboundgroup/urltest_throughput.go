package outboundgroup

import (
	"context"
	"errors"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/singledo"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	urlTestStrategyLatency    = "latency"
	urlTestStrategyThroughput = "throughput"

	defaultThroughputTimeout   = 3000 // ms
	defaultThroughputMaxBytes  = 10 * 1024 * 1024
	defaultThroughputInterval  = 3600 // s
	defaultThroughputTolerance = 10   // percent

	throughputConnectTimeout = 5 * time.Second
	throughputStartupDelay   = 30 * time.Second
)

var errThroughputURL = errors.New("throughput-url is required when strategy is throughput")

type throughputOption struct {
	url       string
	duration  time.Duration
	maxBytes  int64
	interval  time.Duration
	tolerance uint64 // percent
}

func newThroughputOption(opt URLTestOption) (*throughputOption, error) {
	switch opt.Strategy {
	case "", urlTestStrategyLatency:
		return nil, nil
	case urlTestStrategyThroughput:
	default:
		return nil, errors.New("unsupported url-test strategy: " + opt.Strategy)
	}
	if opt.ThroughputURL == "" {
		return nil, errThroughputURL
	}
	o := &throughputOption{
		url:       opt.ThroughputURL,
		duration:  defaultThroughputTimeout * time.Millisecond,
		maxBytes:  defaultThroughputMaxBytes,
		interval:  defaultThroughputInterval * time.Second,
		tolerance: defaultThroughputTolerance,
	}
	if opt.ThroughputTimeout > 0 {
		o.duration = time.Duration(opt.ThroughputTimeout) * time.Millisecond
	}
	if opt.ThroughputMaxBytes > 0 {
		o.maxBytes = opt.ThroughputMaxBytes
	}
	if opt.ThroughputInterval > 0 {
		o.interval = time.Duration(opt.ThroughputInterval) * time.Second
	}
	if opt.ThroughputTolerance != nil {
		if *opt.ThroughputTolerance >= 100 {
			return nil, errors.New("throughput-tolerance must be less than 100")
		}
		o.tolerance = uint64(*opt.ThroughputTolerance)
	}
	return o, nil
}

// throughputTester periodically runs speed tests for the proxies of a url-test group.
// It must not reference the owning URLTest, otherwise the URLTest is never garbage
// collected and the finalizer that stops the tester never runs.
type throughputTester struct {
	*throughputOption
	ctx        context.Context
	cancel     context.CancelFunc
	gb         *GroupBase
	fastSingle *singledo.Single[C.Proxy]
	lazy       bool
	lastTouch  atomic.TypedValue[time.Time]
}

func newThroughputTester(opt *throughputOption, gb *GroupBase, fastSingle *singledo.Single[C.Proxy], lazy bool) *throughputTester {
	ctx, cancel := context.WithCancel(context.Background())
	t := &throughputTester{
		throughputOption: opt,
		ctx:              ctx,
		cancel:           cancel,
		gb:               gb,
		fastSingle:       fastSingle,
		lazy:             lazy,
	}
	go t.loop()
	return t
}

func (t *throughputTester) touch() {
	t.lastTouch.Store(time.Now())
}

func (t *throughputTester) close() {
	t.cancel()
}

func (t *throughputTester) loop() {
	// give health checks a chance to mark dead proxies first
	select {
	case <-time.After(throughputStartupDelay):
	case <-t.ctx.Done():
		return
	}
	t.check()

	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if !t.lazy || time.Since(t.lastTouch.Load()) < t.interval {
				t.check()
			} else {
				log.Debugln("[Throughput] skip once for group [%s] because we are lazy", t.gb.Name())
			}
		case <-t.ctx.Done():
			return
		}
	}
}

func (t *throughputTester) check() {
	proxies := t.gb.GetProxies(false)
	log.Debugln("[Throughput] group [%s] start testing %d proxies", t.gb.Name(), len(proxies))
	for _, proxy := range proxies {
		// results are stored on the proxy, so a proxy shared by several groups
		// with the same throughput-url is tested once per round
		if h, ok := proxy.LastSpeedForTestUrl(t.url); ok && time.Since(h.Time) < t.interval/2 {
			continue
		}
		ctx, cancel := context.WithTimeout(t.ctx, throughputConnectTimeout+t.duration)
		_, err := proxy.SpeedTest(ctx, t.url, t.maxBytes, t.duration)
		cancel()
		if t.ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Debugln("[Throughput] %s speed test failed: %v", proxy.Name(), err)
		}
	}
	t.fastSingle.Reset()
	log.Debugln("[Throughput] group [%s] finished", t.gb.Name())
}

// pick returns the fastest alive proxy; among proxies whose speed is within
// tolerance percent of the fastest one, the lowest latency one wins.
// It returns nil when there is no usable result, so the caller falls back to latency.
func (t *throughputTester) pick(proxies []C.Proxy, testUrl string) C.Proxy {
	speedOf := func(proxy C.Proxy) uint64 {
		if !proxy.AliveForTestUrl(testUrl) {
			return 0
		}
		h, _ := proxy.LastSpeedForTestUrl(t.url)
		return h.Speed
	}

	var maxSpeed uint64
	for _, proxy := range proxies {
		if speed := speedOf(proxy); speed > maxSpeed {
			maxSpeed = speed
		}
	}
	if maxSpeed == 0 {
		return nil
	}

	floor := maxSpeed * (100 - t.tolerance) / 100
	var fast C.Proxy
	for _, proxy := range proxies {
		if speedOf(proxy) < floor || speedOf(proxy) == 0 {
			continue
		}
		if fast == nil || proxy.LastDelayForTestUrl(testUrl) < fast.LastDelayForTestUrl(testUrl) {
			fast = proxy
		}
	}
	return fast
}
