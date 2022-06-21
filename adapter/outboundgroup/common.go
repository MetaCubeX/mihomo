package outboundgroup

import (
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

const (
	defaultGetProxiesDuration = time.Second * 5
)

var defaultRejectProxy = adapter.NewProxy(outbound.NewReject())

func getProvidersProxies(providers []provider.ProxyProvider, touch bool) []C.Proxy {
	proxies := []C.Proxy{}
	for _, pd := range providers {
		if touch {
			proxies = append(proxies, pd.ProxiesWithTouch()...)
		} else {
			proxies = append(proxies, pd.Proxies()...)
		}
	}
	if len(proxies) == 0 {
		proxies = append(proxies, defaultRejectProxy)
	}
	return proxies
}
