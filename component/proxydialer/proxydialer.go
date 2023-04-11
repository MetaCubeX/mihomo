package proxydialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"
	"github.com/Dreamacro/clash/tunnel/statistic"
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
	currentMeta, err := addrToMetadata(address)
	if err != nil {
		return nil, err
	}
	if strings.Contains(network, "udp") { // using in wireguard outbound
		pc, err := p.listenPacket(ctx, currentMeta)
		if err != nil {
			return nil, err
		}
		return N.NewBindPacketConn(pc, currentMeta.UDPAddr()), nil
	}
	var conn C.Conn
	switch p.proxy.SupportWithDialer() {
	case C.ALLNet:
		fallthrough
	case C.TCP:
		conn, err = p.proxy.DialContextWithDialer(ctx, p.dialer, currentMeta)
		if err != nil {
			return nil, err
		}
	default: // fallback to old function
		if d, ok := p.dialer.(dialer.Dialer); ok { // fallback to old function
			conn, err = p.proxy.DialContext(ctx, currentMeta, dialer.WithOption(d.Opt))
			if err != nil {
				return nil, err
			}
		} else {
			return nil, C.ErrNotSupport
		}
	}
	if p.statistic {
		conn = statistic.NewTCPTracker(conn, statistic.DefaultManager, currentMeta, nil, 0, 0, false)
	}
	return conn, err
}

func (p proxyDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	currentMeta, err := addrToMetadata(rAddrPort.String())
	if err != nil {
		return nil, err
	}
	return p.listenPacket(ctx, currentMeta)
}

func (p proxyDialer) listenPacket(ctx context.Context, currentMeta *C.Metadata) (C.PacketConn, error) {
	var pc C.PacketConn
	var err error
	currentMeta.NetWork = C.UDP
	switch p.proxy.SupportWithDialer() {
	case C.ALLNet:
		fallthrough
	case C.UDP:
		pc, err = p.proxy.ListenPacketWithDialer(ctx, p.dialer, currentMeta)
		if err != nil {
			return nil, err
		}
	default: // fallback to old function
		if d, ok := p.dialer.(dialer.Dialer); ok { // fallback to old function
			pc, err = p.proxy.ListenPacketContext(ctx, currentMeta, dialer.WithOption(d.Opt))
			if err != nil {
				return nil, err
			}
		} else {
			return nil, C.ErrNotSupport
		}
	}
	if p.statistic {
		pc = statistic.NewUDPTracker(pc, statistic.DefaultManager, currentMeta, nil, 0, 0, false)
	}
	return pc, nil
}

func addrToMetadata(rawAddress string) (addr *C.Metadata, err error) {
	host, port, err := net.SplitHostPort(rawAddress)
	if err != nil {
		err = fmt.Errorf("addrToMetadata failed: %w", err)
		return
	}

	if ip, err := netip.ParseAddr(host); err != nil {
		addr = &C.Metadata{
			Host:    host,
			DstPort: port,
		}
	} else {
		addr = &C.Metadata{
			Host:    "",
			DstIP:   ip.Unmap(),
			DstPort: port,
		}
	}
	addr.Type = C.INNER

	return
}
