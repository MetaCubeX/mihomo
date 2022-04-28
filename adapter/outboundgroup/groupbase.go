package outboundgroup

import (
	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	types "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/tunnel"
	"github.com/dlclark/regexp2"
)

type GroupBase struct {
	*outbound.Base
	filter    *regexp2.Regexp
	providers []provider.ProxyProvider
	versions  map[string]uint
	proxies   map[string][]C.Proxy
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
		versions:  map[string]uint{},
		proxies:   map[string][]C.Proxy{},
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
				gb.proxies[pd.Name()] = pd.ProxiesWithTouch()
			} else {
				gb.proxies[pd.Name()] = pd.Proxies()
			}

			gb.versions[pd.Name()] = pd.Version()
			continue
		}

		if version, ok := gb.versions[pd.Name()]; !ok || version != pd.Version() {
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

			gb.proxies[pd.Name()] = newProxies
			gb.versions[pd.Name()] = pd.Version()
		}
	}
	var proxies []C.Proxy
	for _, v := range gb.proxies {
		proxies = append(proxies, v...)
	}
	if len(proxies) == 0 {
		return append(proxies, tunnel.Proxies()["COMPATIBLE"])
	}
	return proxies
}
