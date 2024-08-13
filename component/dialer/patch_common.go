//go:build !(android && cmfa)

package dialer

import (
	"context"
	"net"
	"syscall"
)

type SocketControl func(network, address string, conn syscall.RawConn) error

var DefaultSocketHook SocketControl

func dialContextHooked(ctx context.Context, dialer *net.Dialer, network string, address string) (net.Conn, error) {
	return nil, nil
}

func listenPacketHooked(ctx context.Context, network, address string) (net.PacketConn, error) {
	return nil, nil
}
