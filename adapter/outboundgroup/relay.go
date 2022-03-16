package outboundgroup

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/singledo"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

type Relay struct {
	*outbound.Base
	single    *singledo.Single
	providers []provider.ProxyProvider
}

// DialContext implements C.ProxyAdapter
func (r *Relay) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	var proxies []C.Proxy
	for _, proxy := range r.proxies(metadata, true) {
		if proxy.Type() != C.Direct {
			proxies = append(proxies, proxy)
		}
	}

	switch len(proxies) {
	case 0:
		return outbound.NewDirect().DialContext(ctx, metadata, r.Base.DialOptions(opts...)...)
	case 1:
		return proxies[0].DialContext(ctx, metadata, r.Base.DialOptions(opts...)...)
	}

	first := proxies[0]
	last := proxies[len(proxies)-1]

	c, err := dialer.DialContext(ctx, "tcp", first.Addr(), r.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
	}
	tcpKeepAlive(c)

	var currentMeta *C.Metadata
	for _, proxy := range proxies[1:] {
		currentMeta, err = addrToMetadata(proxy.Addr())
		if err != nil {
			return nil, err
		}

		c, err = first.StreamConn(c, currentMeta)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
		}

		first = proxy
	}

	c, err = last.StreamConn(c, metadata)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", last.Addr(), err)
	}

	return outbound.NewConn(c, r), nil
}

// MarshalJSON implements C.ProxyAdapter
func (r *Relay) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range r.rawProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": r.Type().String(),
		"all":  all,
	})
}

func (r *Relay) rawProxies(touch bool) []C.Proxy {
	elm, _, _ := r.single.Do(func() (any, error) {
		return getProvidersProxies(r.providers, touch), nil
	})

	return elm.([]C.Proxy)
}

func (r *Relay) proxies(metadata *C.Metadata, touch bool) []C.Proxy {
	proxies := r.rawProxies(touch)

	for n, proxy := range proxies {
		subproxy := proxy.Unwrap(metadata)
		for subproxy != nil {
			proxies[n] = subproxy
			subproxy = subproxy.Unwrap(metadata)
		}
	}

	return proxies
}

func NewRelay(option *GroupCommonOption, providers []provider.ProxyProvider) *Relay {
	return &Relay{
		Base: outbound.NewBase(outbound.BaseOption{
			Name:        option.Name,
			Type:        C.Relay,
			Interface:   option.Interface,
			RoutingMark: option.RoutingMark,
		}),
		single:    singledo.NewSingle(defaultGetProxiesDuration),
		providers: providers,
	}
}
