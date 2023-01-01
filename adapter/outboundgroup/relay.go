package outboundgroup

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"

	"github.com/Dreamacro/clash/adapter/outbound"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

type Relay struct {
	*GroupBase
}

type proxyDialer struct {
	proxy  C.Proxy
	dialer C.Dialer
}

func (p proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	currentMeta, err := addrToMetadata(address)
	if err != nil {
		return nil, err
	}
	if strings.Contains(network, "udp") { // should not support this operation
		currentMeta.NetWork = C.UDP
		pc, err := p.proxy.ListenPacketWithDialer(ctx, p.dialer, currentMeta)
		if err != nil {
			return nil, err
		}
		return N.NewBindPacketConn(pc, currentMeta.UDPAddr()), nil
	}
	return p.proxy.DialContextWithDialer(ctx, p.dialer, currentMeta)
}

func (p proxyDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	currentMeta, err := addrToMetadata(rAddrPort.String())
	if err != nil {
		return nil, err
	}
	currentMeta.NetWork = C.UDP
	return p.proxy.ListenPacketWithDialer(ctx, p.dialer, currentMeta)
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
		d = proxyDialer{
			proxy:  proxy,
			dialer: d,
		}
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
		d = proxyDialer{
			proxy:  proxy,
			dialer: d,
		}
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
		if !proxy.SupportWithDialer() {
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
