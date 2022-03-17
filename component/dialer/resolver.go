package dialer

import (
	"context"
	"net"
)

func init() {
	// We must use this DialContext to query DNS
	// when using net default resolver.
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = resolverDialContext
}

func resolverDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{}

	interfaceName := DefaultInterface.Load()

	if interfaceName != "" {
		dstIP := net.ParseIP(address)
		if dstIP != nil {
			bindIfaceToDialer(interfaceName, d, network, dstIP)
		}
	}

	return d.DialContext(ctx, network, address)
}
