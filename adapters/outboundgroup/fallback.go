package outboundgroup

import (
	"context"
	"encoding/json"
	"net"

	"github.com/Dreamacro/clash/adapters/outbound"
	"github.com/Dreamacro/clash/adapters/provider"
	C "github.com/Dreamacro/clash/constant"
)

type Fallback struct {
	*outbound.Base
	providers []provider.ProxyProvider
}

func (f *Fallback) Now() string {
	proxy := f.findAliveProxy()
	return proxy.Name()
}

func (f *Fallback) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	proxy := f.findAliveProxy()
	c, err := proxy.DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(f)
	}
	return c, err
}

func (f *Fallback) DialUDP(metadata *C.Metadata) (C.PacketConn, net.Addr, error) {
	proxy := f.findAliveProxy()
	pc, addr, err := proxy.DialUDP(metadata)
	if err == nil {
		pc.AppendToChains(f)
	}
	return pc, addr, err
}

func (f *Fallback) SupportUDP() bool {
	proxy := f.findAliveProxy()
	return proxy.SupportUDP()
}

func (f *Fallback) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range f.proxies() {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]interface{}{
		"type": f.Type().String(),
		"now":  f.Now(),
		"all":  all,
	})
}

func (f *Fallback) proxies() []C.Proxy {
	proxies := []C.Proxy{}
	for _, provider := range f.providers {
		proxies = append(proxies, provider.Proxies()...)
	}
	return proxies
}

func (f *Fallback) findAliveProxy() C.Proxy {
	for _, provider := range f.providers {
		proxies := provider.Proxies()
		for _, proxy := range proxies {
			if proxy.Alive() {
				return proxy
			}
		}
	}

	return f.providers[0].Proxies()[0]
}

func NewFallback(name string, providers []provider.ProxyProvider) *Fallback {
	return &Fallback{
		Base:      outbound.NewBase(name, C.Fallback, false),
		providers: providers,
	}
}
