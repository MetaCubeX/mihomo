package outboundgroup

import (
	"github.com/Dreamacro/clash/tunnel"
	"github.com/dlclark/regexp2"
	"time"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

const (
	defaultGetProxiesDuration = time.Second * 5
)

func getProvidersProxies(providers []provider.ProxyProvider, touch bool, filter string) []C.Proxy {
	proxies := []C.Proxy{}
	for _, provider := range providers {
		if touch {
			proxies = append(proxies, provider.ProxiesWithTouch()...)
		} else {
			proxies = append(proxies, provider.Proxies()...)
		}
	}

	var filterReg *regexp2.Regexp = nil
	var matchedProxies []C.Proxy
	if len(filter) > 0 {
		//filterReg = regexp.MustCompile(filter)
		filterReg = regexp2.MustCompile(filter, 0)
		for _, p := range proxies {
			if p.Type() < 8 {
				matchedProxies = append(matchedProxies, p)
			}

			//if filterReg.MatchString(p.Name()) {
			if mat, _ := filterReg.FindStringMatch(p.Name()); mat != nil {
				matchedProxies = append(matchedProxies, p)
			}
		}

		if len(matchedProxies) > 0 {
			return matchedProxies
		} else {
			return append([]C.Proxy{}, tunnel.Proxies()["COMPATIBLE"])
		}
	} else {
		if len(proxies) == 0 {
			return append(proxies, tunnel.Proxies()["COMPATIBLE"])
		} else {
			return proxies
		}
	}

}
