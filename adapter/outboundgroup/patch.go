package outboundgroup

import (
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

type ProxyGroup interface {
	C.ProxyAdapter

	Providers() []provider.ProxyProvider
	Proxies() []C.Proxy
	Now() string
}

func (f *Fallback) Providers() []provider.ProxyProvider {
	return f.providers
}

func (lb *LoadBalance) Providers() []provider.ProxyProvider {
	return lb.providers
}

func (f *Fallback) Proxies() []C.Proxy {
	return f.GetProxies(false)
}

func (lb *LoadBalance) Proxies() []C.Proxy {
	return lb.GetProxies(false)
}

func (lb *LoadBalance) Now() string {
	return ""
}

func (r *Relay) Providers() []provider.ProxyProvider {
	return r.providers
}

func (r *Relay) Proxies() []C.Proxy {
	return r.GetProxies(false)
}

func (r *Relay) Now() string {
	return ""
}

func (s *Selector) Providers() []provider.ProxyProvider {
	return s.providers
}

func (s *Selector) Proxies() []C.Proxy {
	return s.GetProxies(false)
}

func (u *URLTest) Providers() []provider.ProxyProvider {
	return u.providers
}

func (u *URLTest) Proxies() []C.Proxy {
	return u.GetProxies(false)
}
