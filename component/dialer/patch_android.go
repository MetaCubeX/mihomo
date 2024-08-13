//go:build android && cmfa

package dialer

import (
	"context"
	"net"
	"syscall"
)

type SocketControl func(network, address string, conn syscall.RawConn) error

var DefaultSocketHook SocketControl

func dialContextHooked(ctx context.Context, dialer *net.Dialer, network string, address string) (net.Conn, error) {
	addControlToDialer(dialer, func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return DefaultSocketHook(network, address, c)
	})

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	if t, ok := conn.(*net.TCPConn); ok {
		t.SetKeepAlive(false)
	}

	return conn, nil
}

func listenPacketHooked(ctx context.Context, network, address string) (net.PacketConn, error) {
	lc := &net.ListenConfig{
		Control: DefaultSocketHook,
	}

	return lc.ListenPacket(ctx, network, address)
}
