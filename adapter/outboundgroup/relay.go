package outboundgroup

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
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

	first := proxies[0]
	last := proxies[len(proxies)-1]

	var c net.Conn
	var currentMeta *C.Metadata
	var err error

	currentMeta, err = addrToMetadata(proxies[1].Addr())
	if err != nil {
		return nil, err
	}

	c, err = first.DialContext(ctx, currentMeta, r.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
	}

	first = proxies[1]

	for _, proxy := range proxies[2:] {
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

	conn := outbound.NewConn(c, last)

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

	udtId := -1
	for i, proxy := range proxies {
		if !proxy.SupportUDP() {
			return nil, fmt.Errorf("%s don't support udp", proxy.Name())
		}
		if proxy.SupportUOT() {
			udtId = i // we need the latest id, so don't break
		}
	}

	first := proxies[0]
	last := proxies[len(proxies)-1]

	var pc C.PacketConn
	var currentMeta *C.Metadata
	if udtId != -1 {
		c, err := dialer.DialContext(ctx, "tcp", first.Addr(), r.Base.DialOptions(opts...)...)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
		}
		tcpKeepAlive(c)

		for _, proxy := range proxies[1 : udtId+1] {
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

		if first == last {
			currentMeta = metadata
		} else {
			currentMeta, err = addrToMetadata(proxies[udtId+1].Addr())
			if err != nil {
				return nil, err
			}
			currentMeta.NetWork = C.UDP
		}
		c, err = first.StreamConn(c, currentMeta)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
		}

		pc, err = first.ListenPacketOnStreamConn(c, currentMeta)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
		}
		if first == last {
			return pc, nil
		}
	} else {
		currentMeta, err = addrToMetadata(proxies[1].Addr())
		if err != nil {
			return nil, err
		}
		currentMeta.NetWork = C.UDP
		pc, err = first.ListenPacketContext(ctx, currentMeta, r.Base.DialOptions(opts...)...)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
		}
		udtId = 0
	}

	first = proxies[udtId+1]
	for _, proxy := range proxies[udtId+2:] {
		currentMeta, err = addrToMetadata(proxy.Addr())
		if err != nil {
			return nil, err
		}
		currentMeta.NetWork = C.UDP

		pc, err = first.ListenPacketOnPacketConn(ctx, pc, currentMeta)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
		}

		first = proxy
	}

	pc, err = last.ListenPacketOnPacketConn(ctx, pc, metadata)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", last.Addr(), err)
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
		if !proxy.SupportLPPC() {
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
	proxies, _ := r.proxies(nil, true)
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
			providers,
		}),
	}
}
