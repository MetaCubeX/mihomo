package proxydialer

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/slowdown"
	C "github.com/metacubex/mihomo/constant"
)

type SlowDownDialer struct {
	C.Dialer
	Slowdown *slowdown.SlowDown
}

func (d SlowDownDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return slowdown.Do(d.Slowdown, ctx, func() (net.Conn, error) {
		return d.Dialer.DialContext(ctx, network, address)
	})
}

func (d SlowDownDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return slowdown.Do(d.Slowdown, ctx, func() (net.PacketConn, error) {
		return d.Dialer.ListenPacket(ctx, network, address, rAddrPort)
	})
}

func NewSlowDownDialer(d C.Dialer, sd *slowdown.SlowDown) SlowDownDialer {
	return SlowDownDialer{
		Dialer:   d,
		Slowdown: sd,
	}
}
