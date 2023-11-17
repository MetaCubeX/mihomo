// +build !cmfa

package dialer

import (
	"context"
	"net"
	"net/netip"
)

func dialContextHooked(ctx context.Context, network string, destination netip.Addr, port string) (net.Conn, error) {
	return nil, nil
}

func listenPacketHooked(ctx context.Context, network, address string) (net.PacketConn, error) {
	return nil, nil
}
