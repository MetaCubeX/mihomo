package outboundgroup

import (
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

type ProxyGroup interface {
	C.ProxyAdapter

	Providers() []provider.ProxyProvider
	Now() string
}

func (f *Fallback) Providers() []provider.ProxyProvider {
	return f.providers
}

func (lb *LoadBalance) Providers() []provider.ProxyProvider {
	return lb.providers
}

func (lb *LoadBalance) Now() string {
	return ""
}

func (r *Relay) Providers() []provider.ProxyProvider {
	return r.providers
}

func (r *Relay) Now() string {
	return ""
}

func (s *Selector) Providers() []provider.ProxyProvider {
	return s.providers
}

func (u *URLTest) Providers() []provider.ProxyProvider {
	return u.providers
}
