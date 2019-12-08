package outboundgroup

import (
	"context"
	"encoding/json"
	"net"

	"github.com/Dreamacro/clash/adapters/outbound"
	"github.com/Dreamacro/clash/adapters/provider"
	C "github.com/Dreamacro/clash/constant"
)

type URLTest struct {
	*outbound.Base
	fast      C.Proxy
	providers []provider.ProxyProvider
}

func (u *URLTest) Now() string {
	return u.fast.Name()
}

func (u *URLTest) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	for i := 0; i < 3; i++ {
		c, err = u.fast.DialContext(ctx, metadata)
		if err == nil {
			c.AppendToChains(u)
			return
		}
		u.fallback()
	}
	return
}

func (u *URLTest) DialUDP(metadata *C.Metadata) (C.PacketConn, net.Addr, error) {
	pc, addr, err := u.fast.DialUDP(metadata)
	if err == nil {
		pc.AppendToChains(u)
	}
	return pc, addr, err
}

func (u *URLTest) proxies() []C.Proxy {
	proxies := []C.Proxy{}
	for _, provider := range u.providers {
		proxies = append(proxies, provider.Proxies()...)
	}
	return proxies
}

func (u *URLTest) SupportUDP() bool {
	return u.fast.SupportUDP()
}

func (u *URLTest) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range u.proxies() {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]interface{}{
		"type": u.Type().String(),
		"now":  u.Now(),
		"all":  all,
	})
}

func (u *URLTest) fallback() {
	proxies := u.proxies()
	fast := proxies[0]
	min := fast.LastDelay()
	for _, proxy := range proxies[1:] {
		if !proxy.Alive() {
			continue
		}

		delay := proxy.LastDelay()
		if delay < min {
			fast = proxy
			min = delay
		}
	}
	u.fast = fast
}

func NewURLTest(name string, providers []provider.ProxyProvider) *URLTest {
	fast := providers[0].Proxies()[0]

	return &URLTest{
		Base:      outbound.NewBase(name, C.URLTest, false),
		fast:      fast,
		providers: providers,
	}
}
