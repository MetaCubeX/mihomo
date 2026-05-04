//go:build android

package outbound

import "tailscale.com/net/netmon"

func updateTailscaleAndroidDefaultRoute(ifName string) {
	netmon.UpdateLastKnownDefaultRouteInterface(ifName)
}
