package sing_tun

import (
	"context"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing-tun/ping"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (h *ListenerHandler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	switch network {
	case N.NetworkICMP: // our fork only send those type to PrepareConnection now
		if h.DisableICMPForwarding || resolver.IsFakeIP(destination.Addr) { // skip fakeip and if ICMP handling is disabled
			log.Infoln("[ICMP] %s %s --> %s using fake ping echo", network, source, destination)
			return nil, nil
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
