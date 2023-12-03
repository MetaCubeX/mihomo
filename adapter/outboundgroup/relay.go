package outboundgroup

import (
	"context"
	"encoding/json"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/provider"
)

type Relay struct {
	*GroupBase
}

// DialContext implements C.ProxyAdapter
func (r *Relay) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	proxies, chainProxies := r.proxies(metadata, true)

	switch len(proxies) {
	case 0:
		return outbound.NewDirect().DialContext(ctx, metadata, r.Base.DialOptions(opts...)...)
	case 1:
		return proxies[0].DialContext(ctx, metadata, r.Base.DialOptions(opts...)...)
	}
	var d C.Dialer
	d = dialer.NewDialer(r.Base.DialOptions(opts...)...)
	for _, proxy := range proxies[:len(proxies)-1] {
		d = proxydialer.New(proxy, d, false)
	}
	last := proxies[len(proxies)-1]
	conn, err := last.DialContextWithDialer(ctx, d, metadata)
	if err != nil {
		return nil, err
	}

	for i := len(chainProxies) - 2; i >= 0; i-- {
		conn.AppendToChains(chainProxies[i])
	}

	conn.AppendToChains(r)

	return conn, nil
}

// ListenPacketContext implements C.ProxyAdapter
func (r *Relay) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	proxies, chainProxies := r.proxies(metadata, true)

	switch len(proxies) {
	case 0:
		return outbound.NewDirect().ListenPacketContext(ctx, metadata, r.Base.DialOptions(opts...)...)
	case 1:
		return proxies[0].ListenPacketContext(ctx, metadata, r.Base.DialOptions(opts...)...)
	}

	var d C.Dialer
	d = dialer.NewDialer(r.Base.DialOptions(opts...)...)
	for _, proxy := range proxies[:len(proxies)-1] {
		d = proxydialer.New(proxy, d, false)
	}
	last := proxies[len(proxies)-1]
	pc, err := last.ListenPacketWithDialer(ctx, d, metadata)
	if err != nil {
		return nil, err
	}

	for i := len(chainProxies) - 2; i >= 0; i-- {
		pc.AppendToChains(chainProxies[i])
	}

	pc.AppendToChains(r)

	return pc, nil
}

// SupportUDP implements C.ProxyAdapter
func (r *Relay) SupportUDP() bool {
	proxies, _ := r.proxies(nil, false)
	if len(proxies) == 0 { // C.Direct
		return true
	}
	for i := len(proxies) - 1; i >= 0; i-- {
		proxy := proxies[i]
		if !proxy.SupportUDP() {
			return false
		}
		if proxy.SupportUOT() {
			return true
		}
		switch proxy.SupportWithDialer() {
		case C.ALLNet:
		case C.UDP:
		default: // C.TCP and C.InvalidNet
			return false
		}
	}
	return true
}

// MarshalJSON implements C.ProxyAdapter
func (r *Relay) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range r.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": r.Type().String(),
		"all":  all,
	})
}

func (r *Relay) proxies(metadata *C.Metadata, touch bool) ([]C.Proxy, []C.Proxy) {
	rawProxies := r.GetProxies(touch)

	var proxies []C.Proxy
	var chainProxies []C.Proxy
	var targetProxies []C.Proxy

	for n, proxy := range rawProxies {
		proxies = append(proxies, proxy)
		chainProxies = append(chainProxies, proxy)
		subproxy := proxy.Unwrap(metadata, touch)
		for subproxy != nil {
			chainProxies = append(chainProxies, subproxy)
			proxies[n] = subproxy
			subproxy = subproxy.Unwrap(metadata, touch)
		}
	}

	for _, proxy := range proxies {
		if proxy.Type() != C.Direct && proxy.Type() != C.Compatible {
			targetProxies = append(targetProxies, proxy)
		}
	}

	return targetProxies, chainProxies
}

func (r *Relay) Addr() string {
	proxies, _ := r.proxies(nil, false)
	return proxies[len(proxies)-1].Addr()
}

func NewRelay(option *GroupCommonOption, providers []provider.ProxyProvider) *Relay {
	return &Relay{
		GroupBase: NewGroupBase(GroupBaseOption{
			outbound.BaseOption{
				Name:        option.Name,
				Type:        C.Relay,
				Interface:   option.Interface,
				RoutingMark: option.RoutingMark,
			},
			"",
			"",
			"",
			providers,
		}),
	}
}
