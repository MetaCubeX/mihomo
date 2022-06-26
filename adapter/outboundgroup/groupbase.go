package outboundgroup

import (
	"context"
	"fmt"
	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	types "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"
	"github.com/dlclark/regexp2"
	"go.uber.org/atomic"
	"sync"
	"time"
)

type GroupBase struct {
	*outbound.Base
	filter        *regexp2.Regexp
	providers     []provider.ProxyProvider
	versions      sync.Map // map[string]uint
	proxies       sync.Map // map[string][]C.Proxy
	failedTestMux sync.Mutex
	failedTimes   int
	failedTime    time.Time
	failedTesting *atomic.Bool
}

type GroupBaseOption struct {
	outbound.BaseOption
	filter    string
	providers []provider.ProxyProvider
}

func NewGroupBase(opt GroupBaseOption) *GroupBase {
	var filter *regexp2.Regexp = nil
	if opt.filter != "" {
		filter = regexp2.MustCompile(opt.filter, 0)
	}
	return &GroupBase{
		Base:          outbound.NewBase(opt.BaseOption),
		filter:        filter,
		providers:     opt.providers,
		failedTesting: atomic.NewBool(false),
	}
}

func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {
	if gb.filter == nil {
		var proxies []C.Proxy
		for _, pd := range gb.providers {
			if touch {
				pd.Touch()
			}
			proxies = append(proxies, pd.Proxies()...)
		}
		if len(proxies) == 0 {
			return append(proxies, tunnel.Proxies()["COMPATIBLE"])
		}
		return proxies
	}

	for _, pd := range gb.providers {
		if touch {
			pd.Touch()
		}

		if pd.VehicleType() == types.Compatible {
			gb.proxies.Store(pd.Name(), pd.Proxies())
			gb.versions.Store(pd.Name(), pd.Version())
			continue
		}

		if version, ok := gb.versions.Load(pd.Name()); !ok || version != pd.Version() {
			var (
				proxies    []C.Proxy
				newProxies []C.Proxy
			)

			proxies = pd.Proxies()

			for _, p := range proxies {
				if mat, _ := gb.filter.FindStringMatch(p.Name()); mat != nil {
					newProxies = append(newProxies, p)
				}
			}

			gb.proxies.Store(pd.Name(), newProxies)
			gb.versions.Store(pd.Name(), pd.Version())
		}
	}
	var proxies []C.Proxy
	gb.proxies.Range(func(key, value any) bool {
		proxies = append(proxies, value.([]C.Proxy)...)
		return true
	})
	if len(proxies) == 0 {
		return append(proxies, tunnel.Proxies()["COMPATIBLE"])
	}
	return proxies
}

func (gb *GroupBase) URLTest(ctx context.Context, url string) (map[string]uint16, error) {
	var wg sync.WaitGroup
	var lock sync.Mutex
	mp := map[string]uint16{}
	proxies := gb.GetProxies(false)
	for _, proxy := range proxies {
		proxy := proxy
		wg.Add(1)
		go func() {
			delay, err := proxy.URLTest(ctx, url)
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

func (gb *GroupBase) onDialFailed() {
	if gb.failedTesting.Load() {
		return
	}

	go func() {
		gb.failedTestMux.Lock()
		defer gb.failedTestMux.Unlock()

		gb.failedTimes++
		if gb.failedTimes == 1 {
			log.Debugln("ProxyGroup: %s first failed", gb.Name())
			gb.failedTime = time.Now()
		} else {
			if time.Since(gb.failedTime) > gb.failedTimeoutInterval() {
				return
			}

			log.Debugln("ProxyGroup: %s failed count: %d", gb.Name(), gb.failedTimes)
			if gb.failedTimes >= gb.maxFailedTimes() {
				gb.failedTesting.Store(true)
				log.Warnln("because %s failed multiple times, active health check", gb.Name())
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
		}
	}()
}

func (gb *GroupBase) failedIntervalTime() int64 {
	return 5 * time.Second.Milliseconds()
}

func (gb *GroupBase) onDialSuccess() {
	if !gb.failedTesting.Load() {
		gb.failedTimes = 0
	}
}

func (gb *GroupBase) maxFailedTimes() int {
	return 5
}

func (gb *GroupBase) failedTimeoutInterval() time.Duration {
	return 5 * time.Second
}
