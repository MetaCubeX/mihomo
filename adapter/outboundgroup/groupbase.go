package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/exp/slices"
)

type GroupBase struct {
	*outbound.Base
	hidden            bool
	icon              string
	filterRegs        []*regexp2.Regexp
	excludeFilterRegs []*regexp2.Regexp
	excludeTypeArray  []string
	providers         []P.ProxyProvider
	failedTestMux     sync.Mutex
	failedTimes       int
	failedTime        time.Time
	failedTesting     atomic.Bool
	lastForcedCheck   atomic.TypedValue[time.Time]
	testTimeout       int
	maxFailedTimes    int
	interval          time.Duration
	emptyFallback     C.Proxy

	// for GetProxies
	getProxiesMutex  sync.Mutex
	providerVersions []uint32
	providerProxies  []C.Proxy
}

type GroupBaseOption struct {
	Name           string
	Type           C.AdapterType
	Hidden         bool
	Icon           string
	Filter         string
	ExcludeFilter  string
	ExcludeType    string
	TestTimeout    int
	MaxFailedTimes int
	Interval       int
	EmptyFallback  C.Proxy
	Providers      []P.ProxyProvider
}

func NewGroupBase(opt GroupBaseOption) *GroupBase {
	var excludeTypeArray []string
	if opt.ExcludeType != "" {
		excludeTypeArray = strings.Split(opt.ExcludeType, "|")
	}

	var excludeFilterRegs []*regexp2.Regexp
	if opt.ExcludeFilter != "" {
		for _, excludeFilter := range strings.Split(opt.ExcludeFilter, "`") {
			excludeFilterReg := regexp2.MustCompile(excludeFilter, regexp2.None)
			excludeFilterRegs = append(excludeFilterRegs, excludeFilterReg)
		}
	}

	var filterRegs []*regexp2.Regexp
	if opt.Filter != "" {
		for _, filter := range strings.Split(opt.Filter, "`") {
			filterReg := regexp2.MustCompile(filter, regexp2.None)
			filterRegs = append(filterRegs, filterReg)
		}
	}

	gb := &GroupBase{
		Base:              outbound.NewBase(outbound.BaseOption{Name: opt.Name, Type: opt.Type}),
		hidden:            opt.Hidden,
		icon:              opt.Icon,
		filterRegs:        filterRegs,
		excludeFilterRegs: excludeFilterRegs,
		excludeTypeArray:  excludeTypeArray,
		providers:         opt.Providers,
		failedTesting:     atomic.NewBool(false),
		testTimeout:       opt.TestTimeout,
		maxFailedTimes:    opt.MaxFailedTimes,
		interval:          time.Duration(opt.Interval) * time.Second,
		emptyFallback:     opt.EmptyFallback,
	}

	if gb.testTimeout == 0 {
		gb.testTimeout = 5000
	}
	if gb.maxFailedTimes == 0 {
		gb.maxFailedTimes = 5
	}

	return gb
}

func (gb *GroupBase) Hidden() bool {
	return gb.hidden
}

func (gb *GroupBase) Icon() string {
	return gb.icon
}

func (gb *GroupBase) EmptyFallback() C.Proxy {
	return gb.emptyFallback
}

func (gb *GroupBase) Touch() {
	for _, pd := range gb.providers {
		pd.Touch()
	}
}

func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {
	providerVersions := make([]uint32, len(gb.providers))
	for i, pd := range gb.providers {
		if touch { // touch first
			pd.Touch()
		}
		providerVersions[i] = pd.Version()
	}

	// thread safe
	gb.getProxiesMutex.Lock()
	defer gb.getProxiesMutex.Unlock()

	// return the cached proxies if version not changed
	if slices.Equal(providerVersions, gb.providerVersions) {
		return gb.providerProxies
	}

	var proxies []C.Proxy
	if len(gb.filterRegs) == 0 {
		for _, pd := range gb.providers {
			proxies = append(proxies, pd.Proxies()...)
		}
	} else {
		for _, pd := range gb.providers {
			if pd.VehicleType() == P.Compatible { // compatible provider unneeded filter
				proxies = append(proxies, pd.Proxies()...)
				continue
			}

			var newProxies []C.Proxy
			proxiesSet := map[string]struct{}{}
			for _, filterReg := range gb.filterRegs {
				for _, p := range pd.Proxies() {
					name := p.Name()
					if mat, _ := filterReg.MatchString(name); mat {
						if _, ok := proxiesSet[name]; !ok {
							proxiesSet[name] = struct{}{}
							newProxies = append(newProxies, p)
						}
					}
				}
			}
			proxies = append(proxies, newProxies...)
		}
	}

	// Multiple filers means that proxies are sorted in the order in which the filers appear.
	// Although the filter has been performed once in the previous process,
	// when there are multiple providers, the array needs to be reordered as a whole.
	if len(gb.providers) > 1 && len(gb.filterRegs) > 1 {
		var newProxies []C.Proxy
		proxiesSet := map[string]struct{}{}
		for _, filterReg := range gb.filterRegs {
			for _, p := range proxies {
				name := p.Name()
				if mat, _ := filterReg.MatchString(name); mat {
					if _, ok := proxiesSet[name]; !ok {
						proxiesSet[name] = struct{}{}
						newProxies = append(newProxies, p)
					}
				}
			}
		}
		for _, p := range proxies { // add not matched proxies at the end
			name := p.Name()
			if _, ok := proxiesSet[name]; !ok {
				proxiesSet[name] = struct{}{}
				newProxies = append(newProxies, p)
			}
		}
		proxies = newProxies
	}

	if len(gb.excludeFilterRegs) > 0 {
		var newProxies []C.Proxy
	LOOP1:
		for _, p := range proxies {
			name := p.Name()
			for _, excludeFilterReg := range gb.excludeFilterRegs {
				if mat, _ := excludeFilterReg.MatchString(name); mat {
					continue LOOP1
				}
			}
			newProxies = append(newProxies, p)
		}
		proxies = newProxies
	}

	if gb.excludeTypeArray != nil {
		var newProxies []C.Proxy
	LOOP2:
		for _, p := range proxies {
			mType := p.Type().String()
			for _, excludeType := range gb.excludeTypeArray {
				if strings.EqualFold(mType, excludeType) {
					continue LOOP2
				}
			}
			newProxies = append(newProxies, p)
		}
		proxies = newProxies
	}

	if len(proxies) == 0 {
		return []C.Proxy{gb.EmptyFallback()}
	}

	// only cache when proxies not empty
	gb.providerVersions = providerVersions
	gb.providerProxies = proxies

	return proxies
}

func (gb *GroupBase) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	var wg sync.WaitGroup
	var lock sync.Mutex
	mp := map[string]uint16{}
	proxies := gb.GetProxies(false)
	for _, proxy := range proxies {
		proxy := proxy
		wg.Add(1)
		go func() {
			delay, err := proxy.URLTest(ctx, url, expectedStatus)
			if err == nil {
				lock.Lock()
				mp[proxy.Name()] = delay
				lock.Unlock()
			}

			wg.Done()
		}()
	}
	wg.Wait()

	if len(mp) == 0 {
		return mp, fmt.Errorf("get delay: all proxies timeout")
	} else {
		return mp, nil
	}
}

func (gb *GroupBase) onDialFailed(adapterType C.AdapterType, err error, fn func()) {
	if adapterType == C.Direct || adapterType == C.Compatible || adapterType == C.Reject || adapterType == C.Pass || adapterType == C.RejectDrop {
		return
	}

	if errors.Is(err, C.ErrNotSupport) {
		return
	}

	go func() {
		if strings.Contains(err.Error(), "connection refused") {
			fn()
			return
		}

		gb.failedTestMux.Lock()
		defer gb.failedTestMux.Unlock()

		gb.failedTimes++
		if gb.failedTimes == 1 {
			log.Debugln("ProxyGroup: %s first failed", gb.Name())
			gb.failedTime = time.Now()
		} else {
			if time.Since(gb.failedTime) > time.Duration(gb.testTimeout)*time.Millisecond {
				gb.failedTimes = 0
				return
			}

			log.Debugln("ProxyGroup: %s failed count: %d", gb.Name(), gb.failedTimes)
			if gb.failedTimes >= gb.maxFailedTimes {
				log.Warnln("because %s failed multiple times, activate health check", gb.Name())
				fn()
				gb.failedTimes = 0
			}
		}
	}()
}

// minForcedHealthCheckCooldown is the floor applied when a group has no
// configured interval: rescanning every provider node on each burst of
// failed dials floods the network when a group holds hundreds of proxies.
const minForcedHealthCheckCooldown = 30 * time.Second

// forcedHealthCheckCooldown limits how often a failure-triggered health
// check may run: it must never rescan the group's providers more often than
// the group's own configured interval, otherwise a persistently failing
// group gets rescanned in full every ~30s regardless of what interval the
// user configured.
func (gb *GroupBase) forcedHealthCheckCooldown() time.Duration {
	if gb.interval > 0 {
		return gb.interval
	}
	return minForcedHealthCheckCooldown
}

func (gb *GroupBase) healthCheck() {
	if gb.failedTesting.Load() {
		return
	}

	if time.Since(gb.lastForcedCheck.Load()) < gb.forcedHealthCheckCooldown() {
		return
	}
	gb.lastForcedCheck.Store(time.Now())

	gb.failedTesting.Store(true)
	wg := sync.WaitGroup{}
	for _, proxyProvider := range gb.providers {
		wg.Add(1)
		proxyProvider := proxyProvider
		go func() {
			defer wg.Done()
			proxyProvider.HealthCheck()
		}()
	}

	wg.Wait()
	gb.failedTesting.Store(false)
	gb.failedTimes = 0
}

// resolvesToReject reports whether traffic sent to proxy would currently be
// blackholed: the proxy itself is a REJECT, or it is a group (e.g. an empty
// url-test serving its empty-fallback) whose current pick unwraps to one.
func resolvesToReject(proxy C.Proxy) bool {
	for p := proxy; p != nil; p = p.Unwrap(nil, false) {
		switch p.Type() {
		case C.Reject, C.RejectDrop:
			return true
		}
	}
	return false
}

// forcedHealthCheckNeeded reports whether traffic is being served by a proxy
// that resolves to REJECT: an empty group resolved to its empty-fallback,
// whose dials "succeed" on a nop connection and therefore never reach
// onDialFailed. A plain dead member is deliberately excluded here - it
// already fails dials naturally and is handled by onDialFailed's
// failedTimes/maxFailedTimes/cooldown gate; triggering here too would bypass
// that gate on every single dial and storm the group's health check.
func forcedHealthCheckNeeded(proxy C.Proxy, testUrl string) bool {
	return resolvesToReject(proxy)
}

func (gb *GroupBase) onDialSuccess() {
	if !gb.failedTesting.Load() {
		gb.failedTimes = 0
	}
}
