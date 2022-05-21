package outboundgroup

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/singledo"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

type Relay struct {
	*outbound.Base
	single    *singledo.Single[[]C.Proxy]
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

// ListenPacketContext implements C.ProxyAdapter
func (r *Relay) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	var proxies []C.Proxy
	for _, proxy := range r.proxies(metadata, true) {
		if proxy.Type() != C.Direct {
			proxies = append(proxies, proxy)
		}
	}

	switch len(proxies) {
	case 0:
		return outbound.NewDirect().ListenPacketContext(ctx, metadata, r.Base.DialOptions(opts...)...)
	case 1:
		proxy := proxies[0]
		if !proxy.SupportUDP() {
			return nil, fmt.Errorf("%s connect error: proxy [%s] UDP is not supported", proxy.Addr(), proxy.Name())
		}
		return proxy.ListenPacketContext(ctx, metadata, r.Base.DialOptions(opts...)...)
	}

	var (
		first              = proxies[0]
		last               = proxies[len(proxies)-1]
		rawUDPRelay        bool
		udpOverTCPEndIndex = -1

		c           net.Conn
		err         error
		currentMeta *C.Metadata
	)

	if !last.SupportUDP() {
		return nil, fmt.Errorf("%s connect error: proxy [%s] UDP is not supported in relay chains", last.Addr(), last.Name())
	}

	rawUDPRelay, udpOverTCPEndIndex = isRawUDPRelay(proxies)

	if rawUDPRelay {
		var pc net.PacketConn
		pc, err = dialer.ListenPacket(ctx, "udp", "", r.Base.DialOptions(opts...)...)
		c = outbound.WrapConn(pc)
	} else {
		c, err = dialer.DialContext(ctx, "tcp", first.Addr(), r.Base.DialOptions(opts...)...)
	}

	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
	}

	defer func() {
		if err != nil && c != nil {
			_ = c.Close()
		}
	}()

	for i, proxy := range proxies[1:] {
		currentMeta, err = addrToMetadata(proxy.Addr())
		if err != nil {
			return nil, err
		}

		if outbound.IsPacketConn(c) || udpOverTCPEndIndex == i {
			if !isRawUDP(first) && !first.SupportUDP() {
				return nil, fmt.Errorf("%s connect error: proxy [%s] UDP is not supported in relay chains", first.Addr(), first.Name())
			}

			if !currentMeta.Resolved() && needResolveIP(first) {
				var ip netip.Addr
				ip, err = resolver.ResolveProxyServerHost(currentMeta.Host)
				if err != nil {
					return nil, fmt.Errorf("can't resolve ip: %w", err)
				}
				currentMeta.DstIP = ip
			}

			currentMeta.NetWork = C.UDP
			c, err = first.StreamPacketConn(c, currentMeta)
		} else {
			c, err = first.StreamConn(c, currentMeta)
		}

		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
		}

		first = proxy
	}

	c, err = last.StreamPacketConn(c, metadata)

	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", first.Addr(), err)
	}

	return outbound.NewPacketConn(c.(net.PacketConn), r), nil
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
	elm, _, _ := r.single.Do(func() ([]C.Proxy, error) {
		return getProvidersProxies(r.providers, touch), nil
	})

	return elm
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

func isRawUDPRelay(proxies []C.Proxy) (bool, int) {
	var (
		lastIndex          = len(proxies) - 1
		isLastRawUDP       = isRawUDP(proxies[lastIndex])
		isUDPOverTCP       = false
		udpOverTCPEndIndex = -1
	)

	for i := lastIndex; i >= 0; i-- {
		p := proxies[i]

		isUDPOverTCP = isUDPOverTCP || !isRawUDP(p)

		if isLastRawUDP && isUDPOverTCP && udpOverTCPEndIndex == -1 {
			udpOverTCPEndIndex = i
		}
	}

	return !isUDPOverTCP, udpOverTCPEndIndex
}

func isRawUDP(proxy C.ProxyAdapter) bool {
	if proxy.Type() == C.Shadowsocks || proxy.Type() == C.ShadowsocksR {
		return true
	}
	return false
}

func needResolveIP(proxy C.ProxyAdapter) bool {
	if proxy.Type() == C.Vmess || proxy.Type() == C.Vless {
		return true
	}
	return false
}

func NewRelay(option *GroupCommonOption, providers []provider.ProxyProvider) *Relay {
	return &Relay{
		Base: outbound.NewBase(outbound.BaseOption{
			Name:        option.Name,
			Type:        C.Relay,
			UDP:         true,
			Interface:   option.Interface,
			RoutingMark: option.RoutingMark,
		}),
		single:    singledo.NewSingle[[]C.Proxy](defaultGetProxiesDuration),
		providers: providers,
	}
}
