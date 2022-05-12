package outboundgroup

import (
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
	filter      *regexp2.Regexp
	providers   []provider.ProxyProvider
	versions    sync.Map // map[string]uint
	proxies     sync.Map // map[string][]C.Proxy
	failedTimes *atomic.Int32
	failedTime  *atomic.Int64
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
		Base:        outbound.NewBase(opt.BaseOption),
		filter:      filter,
		providers:   opt.providers,
		failedTimes: atomic.NewInt32(-1),
		failedTime:  atomic.NewInt64(-1),
	}
}

func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {
	if gb.filter == nil {
		var proxies []C.Proxy
		for _, pd := range gb.providers {
			if touch {
				proxies = append(proxies, pd.ProxiesWithTouch()...)
			} else {
				proxies = append(proxies, pd.Proxies()...)
			}
		}
		if len(proxies) == 0 {
			return append(proxies, tunnel.Proxies()["COMPATIBLE"])
		}
		return proxies
	}

	for _, pd := range gb.providers {
		if pd.VehicleType() == types.Compatible {
			if touch {
				gb.proxies.Store(pd.Name(), pd.ProxiesWithTouch())
			} else {
				gb.proxies.Store(pd.Name(), pd.Proxies())
			}

			gb.versions.Store(pd.Name(), pd.Version())
			continue
		}

		if version, ok := gb.versions.Load(pd.Name()); !ok || version != pd.Version() {
			var (
				proxies    []C.Proxy
				newProxies []C.Proxy
			)

			if touch {
				proxies = pd.ProxiesWithTouch()
			} else {
				proxies = pd.Proxies()
			}

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

func (gb *GroupBase) onDialFailed() {
	if gb.failedTime.Load() == -1 {
		log.Warnln("%s first failed", gb.Name())
		now := time.Now().UnixMilli()
		gb.failedTime.Store(now)
		gb.failedTimes.Store(1)
	} else {
		if gb.failedTime.Load()-time.Now().UnixMilli() > gb.failedIntervalTime() {
			gb.failedTimes.Store(-1)
			gb.failedTime.Store(-1)
		} else {
			failedCount := gb.failedTimes.Inc()
			log.Warnln("%s failed count: %d", gb.Name(), failedCount)
			if failedCount >= gb.maxFailedTimes() {
				log.Warnln("because %s failed multiple times, active health check", gb.Name())
				for _, proxyProvider := range gb.providers {
					go proxyProvider.HealthCheck()
				}

				gb.failedTimes.Store(-1)
				gb.failedTime.Store(-1)
			}
		}
	}
}

func (gb *GroupBase) failedIntervalTime() int64 {
	return 5 * time.Second.Milliseconds()
}

func (gb *GroupBase) onDialSuccess() {
	gb.failedTimes.Store(-1)
	gb.failedTime.Store(-1)
}

func (gb *GroupBase) maxFailedTimes() int32 {
	return 5
}
