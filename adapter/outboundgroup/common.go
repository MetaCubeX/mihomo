package outboundgroup

import (
	"regexp"
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
	var filterReg *regexp.Regexp = nil
	matchedProxies := []C.Proxy{}
	if len(filter) > 0 {
		filterReg = regexp.MustCompile(filter)
		for _, p := range proxies {
			if filterReg.MatchString(p.Name()) {
				matchedProxies = append(matchedProxies, p)
			}
		}
		//if no proxy matched, means bad filter, return all proxies
		if len(matchedProxies) > 0 {
			proxies = matchedProxies
		}
	}
	return proxies
}
