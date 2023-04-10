package proxydialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"
)

type proxyDialer struct {
	proxy  C.Proxy
	dialer C.Dialer
}

func New(proxy C.Proxy, dialer C.Dialer) C.Dialer {
	return proxyDialer{proxy: proxy, dialer: dialer}
}

func NewByName(proxyName string, dialer C.Dialer) (C.Dialer, error) {
	proxies := tunnel.Proxies()
	if proxy, ok := proxies[proxyName]; ok {
		return New(proxy, dialer), nil
	}
	return nil, fmt.Errorf("proxyName[%s] not found", proxyName)
}

func (p proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	currentMeta, err := addrToMetadata(address)
	if err != nil {
		return nil, err
	}
	if strings.Contains(network, "udp") { // using in wireguard outbound
		currentMeta.NetWork = C.UDP
		pc, err := p.proxy.ListenPacketWithDialer(ctx, p.dialer, currentMeta)
		if err != nil {
			return nil, err
		}
		return N.NewBindPacketConn(pc, currentMeta.UDPAddr()), nil
	}
	return p.proxy.DialContextWithDialer(ctx, p.dialer, currentMeta)
}

func (p proxyDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	currentMeta, err := addrToMetadata(rAddrPort.String())
	if err != nil {
		return nil, err
	}
	currentMeta.NetWork = C.UDP
	return p.proxy.ListenPacketWithDialer(ctx, p.dialer, currentMeta)
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

	return
}
