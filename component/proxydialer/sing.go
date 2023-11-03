package proxydialer

import (
	"context"
	"net"

	C "github.com/metacubex/mihomo/constant"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type SingDialer interface {
	N.Dialer
	SetDialer(dialer C.Dialer)
}

type singDialer proxyDialer

var _ N.Dialer = (*singDialer)(nil)

func (d *singDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (*proxyDialer)(d).DialContext(ctx, network, destination.String())
}

func (d *singDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return (*proxyDialer)(d).ListenPacket(ctx, "udp", "", destination.AddrPort())
}

func (d *singDialer) SetDialer(dialer C.Dialer) {
	(*proxyDialer)(d).dialer = dialer
}

func NewSingDialer(proxy C.ProxyAdapter, dialer C.Dialer, statistic bool) SingDialer {
	return (*singDialer)(&proxyDialer{
		proxy:     proxy,
		dialer:    dialer,
		statistic: statistic,
	})
}

type byNameSingDialer struct {
	dialer    C.Dialer
	proxyName string
}

var _ N.Dialer = (*byNameSingDialer)(nil)

func (d *byNameSingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var cDialer C.Dialer = d.dialer
	if len(d.proxyName) > 0 {
		pd, err := NewByName(d.proxyName, d.dialer)
		if err != nil {
			return nil, err
		}
		cDialer = pd
	}
	return cDialer.DialContext(ctx, network, destination.String())
}

func (d *byNameSingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	var cDialer C.Dialer = d.dialer
	if len(d.proxyName) > 0 {
		pd, err := NewByName(d.proxyName, d.dialer)
		if err != nil {
			return nil, err
		}
		cDialer = pd
	}
	return cDialer.ListenPacket(ctx, "udp", "", destination.AddrPort())
}

func (d *byNameSingDialer) SetDialer(dialer C.Dialer) {
	d.dialer = dialer
}

func NewByNameSingDialer(proxyName string, dialer C.Dialer) SingDialer {
	return &byNameSingDialer{
		dialer:    dialer,
		proxyName: proxyName,
	}
}
