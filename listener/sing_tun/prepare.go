package sing_tun

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing-tun/ping"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (h *ListenerHandler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	switch network {
	case N.NetworkICMP: // our fork only send those type to PrepareConnection now
		if h.DisableICMPForwarding || h.skipPingForwardingByAddr(destination.Addr) { // skip if ICMP handling is disabled or other condition
			log.Infoln("[ICMP] %s %s --> %s using fake ping echo", network, source, destination)
			return nil, nil
		}
		if router, ok := h.Tunnel.(C.ICMPRouter); ok {
			metadata := &C.Metadata{NetWork: C.ICMP, Type: h.Type, SrcIP: source.Addr, DstIP: destination.Addr}
			inbound.ApplyAdditions(metadata, h.Additions...)
			proxy, err := router.ResolveICMP(metadata)
			if err != nil {
				return nil, err
			}
			if proxy.Type() == C.Reject || proxy.Type() == C.RejectDrop {
				return nil, fmt.Errorf("ICMP rejected by %s", proxy.Name())
			}
			if echo, ok := proxy.Adapter().(C.ICMPEchoProxy); ok && echo.SupportICMP() {
				log.Infoln("[ICMP] %s --> %s using %s", source, destination, proxy.Name())
				return newICMPEchoDestination(source.Addr, destination.Addr, routeContext, timeout, func(ctx context.Context, _ netip.Addr) error {
					return echo.PingICMP(ctx, metadata.DstIP)
				}), nil
			}
			// A Tailscale failure must never send private Tailnet traffic to WAN.
			if proxy.Type() == C.Tailscale {
				return nil, C.ErrNotSupport
			}
			// Preserve existing DIRECT behavior for other adapters without ICMP support.
		}
		log.Infoln("[ICMP] %s %s --> %s using DIRECT", network, source, destination)
		directRouteDestination, err := ping.ConnectDestination(context.TODO(), log.SingLogger, dialer.ICMPControl(destination.Addr), destination.Addr, routeContext, timeout)
		if err != nil {
			log.Warnln("[ICMP] failed to connect to %s", destination)
			return nil, err
		}
		log.Debugln("[ICMP] success connect to %s", destination)
		return directRouteDestination, nil
	}
	return nil, nil
}

func (h *ListenerHandler) skipPingForwardingByAddr(addr netip.Addr) bool {
	for _, prefix := range h.Inet4Address { // skip in interface ipv4 range
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, prefix := range h.Inet6Address { // skip in interface ipv6 range
		if prefix.Contains(addr) {
			return true
		}
	}
	if resolver.IsFakeIP(addr) { // skip in fakeIp pool
		return true
	}
	return false
}
