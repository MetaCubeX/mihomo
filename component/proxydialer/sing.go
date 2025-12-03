package proxydialer

import (
	"context"
	"net"

	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type SingDialer interface {
	N.Dialer
}

type singDialer struct {
	cDialer C.Dialer
}

var _ N.Dialer = (*singDialer)(nil)

func (d singDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.cDialer.DialContext(ctx, network, destination.String())
}

func (d singDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.cDialer.ListenPacket(ctx, "udp", "", destination.AddrPort())
}

func NewSingDialer(cDialer C.Dialer) SingDialer {
	return singDialer{cDialer: cDialer}
}
