package sing_tun

import (
	"context"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing-tun/ping"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (h *ListenerHandler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext) (tun.DirectRouteDestination, error) {
	switch network {
	case N.NetworkICMPv4, N.NetworkICMPv6: // our fork only send those type to PrepareConnection now
		log.Infoln("[ICMP] %s %s --> %s using DIRECT", network, source, destination)
		directRouteDestination, err := ping.ConnectDestination(context.TODO(), log.SingLogger, dialer.ICMPControl(destination.Addr), destination.Addr, routeContext)
		if err != nil {
			log.Warnln("[ICMP] failed to connect to %s", destination)
			return nil, err
		}
		log.Debugln("[ICMP] success connect to %s", destination)
		return directRouteDestination, nil
	}
	return nil, nil
}
