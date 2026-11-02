//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

type tailscalePacketDialer interface {
	ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error)
}

// listenTailscaleProxyPacket creates an unbound, multi-destination UDP
// association through the configured proxy. An unspecified address is valid
// metadata; an invalid AddrPort instead asks proxy adapters to resolve "".
func listenTailscaleProxyPacket(ctx context.Context, d tailscalePacketDialer, network, address string) (net.PacketConn, error) {
	ip := netip.IPv4Unspecified()
	switch network {
	case "udp", "udp4":
	case "udp6":
		ip = netip.IPv6Unspecified()
	default:
		return nil, fmt.Errorf("unsupported Tailscale packet network %q", network)
	}
	local, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	if local.IP == nil {
		local.IP = net.IP(ip.AsSlice())
	}
	pc, err := d.ListenPacket(ctx, network, address, netip.AddrPortFrom(ip, 0))
	if err != nil {
		return nil, err
	}
	if actual, err := tailscaleUDPAddress(pc.LocalAddr()); err == nil {
		local = actual
	}
	// Proxy PacketConns may expose opaque session IDs as their local address.
	// Tailscale expects IP/port addresses for both local and received endpoints.
	return &tailscaleProxyPacketConn{PacketConn: pc, local: local}, nil
}

type tailscaleProxyPacketConn struct {
	net.PacketConn
	local *net.UDPAddr
}

func (c *tailscaleProxyPacketConn) LocalAddr() net.Addr { return c.local }

func (c *tailscaleProxyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}
	udp, err := tailscaleUDPAddress(addr)
	if err != nil {
		return n, nil, err
	}
	return n, udp, nil
}

func tailscaleUDPAddress(addr net.Addr) (*net.UDPAddr, error) {
	for depth := 0; depth < 8 && addr != nil; depth++ {
		if udp, ok := addr.(*net.UDPAddr); ok {
			return udp, nil
		}
		if raw, ok := addr.(interface{ RawAddr() net.Addr }); ok {
			addr = raw.RawAddr()
			continue
		}
		if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
			return net.UDPAddrFromAddrPort(ap), nil
		}
		break
	}
	return nil, fmt.Errorf("Tailscale proxy returned a non-IP UDP address %v", addr)
}
