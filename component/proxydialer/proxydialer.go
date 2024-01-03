package proxydialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type proxyDialer struct {
	proxy     C.ProxyAdapter
	dialer    C.Dialer
	statistic bool
}

func New(proxy C.ProxyAdapter, dialer C.Dialer, statistic bool) C.Dialer {
	return proxyDialer{proxy: proxy, dialer: dialer, statistic: statistic}
}

func NewByName(proxyName string, dialer C.Dialer) (C.Dialer, error) {
	proxies := tunnel.Proxies()
	if proxy, ok := proxies[proxyName]; ok {
		return New(proxy, dialer, true), nil
	}
	return nil, fmt.Errorf("proxyName[%s] not found", proxyName)
}

func (p proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	currentMeta := &C.Metadata{Type: C.INNER}
	if err := currentMeta.SetRemoteAddress(address); err != nil {
		return nil, err
	}
	if strings.Contains(network, "udp") { // using in wireguard outbound
		if !currentMeta.Resolved() {
			ip, err := resolver.ResolveIP(ctx, currentMeta.Host)
			if err != nil {
				return nil, errors.New("can't resolve ip")
			}
			currentMeta.DstIP = ip
		}
		pc, err := p.listenPacket(ctx, currentMeta)
		if err != nil {
			return nil, err
		}
		return N.NewBindPacketConn(pc, currentMeta.UDPAddr()), nil
	}
	var conn C.Conn
	var err error
	if d, ok := p.dialer.(dialer.Dialer); ok { // first using old function to let mux work
		conn, err = p.proxy.DialContext(ctx, currentMeta, dialer.WithOption(d.Opt))
	} else {
		conn, err = p.proxy.DialContextWithDialer(ctx, p.dialer, currentMeta)
	}
	if err != nil {
		return nil, err
	}
	if p.statistic {
		conn = statistic.NewTCPTracker(conn, statistic.DefaultManager, currentMeta, nil, 0, 0, false)
	}
	return conn, err
}

func (p proxyDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	currentMeta := &C.Metadata{Type: C.INNER, DstIP: rAddrPort.Addr(), DstPort: rAddrPort.Port()}
	return p.listenPacket(ctx, currentMeta)
}

func (p proxyDialer) listenPacket(ctx context.Context, currentMeta *C.Metadata) (C.PacketConn, error) {
	var pc C.PacketConn
	var err error
	currentMeta.NetWork = C.UDP
	if d, ok := p.dialer.(dialer.Dialer); ok { // first using old function to let mux work
		pc, err = p.proxy.ListenPacketContext(ctx, currentMeta, dialer.WithOption(d.Opt))
	} else {
		pc, err = p.proxy.ListenPacketWithDialer(ctx, p.dialer, currentMeta)
	}
	if err != nil {
		return nil, err
	}
	if p.statistic {
		pc = statistic.NewUDPTracker(pc, statistic.DefaultManager, currentMeta, nil, 0, 0, false)
	}
	return pc, nil
}
