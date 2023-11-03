package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

type SocketControl func(network, address string, conn syscall.RawConn) error

var DefaultSocketHook SocketControl

func dialContextHooked(ctx context.Context, network string, destination netip.Addr, port string) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: DefaultSocketHook,
	}

	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(destination.String(), port))
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
