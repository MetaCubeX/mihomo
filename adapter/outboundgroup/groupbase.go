package outboundgroup

import (
	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	types "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/tunnel"
	"github.com/dlclark/regexp2"
	"sync"
)

type GroupBase struct {
	*outbound.Base
	filter    *regexp2.Regexp
	providers []provider.ProxyProvider
	versions  sync.Map // map[string]uint
	proxies   sync.Map // map[string][]C.Proxy
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
		Base:      outbound.NewBase(opt.BaseOption),
		filter:    filter,
		providers: opt.providers,
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
	//TODO("Touch Version 没变的")
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
