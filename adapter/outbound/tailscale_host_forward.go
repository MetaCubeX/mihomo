//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

type TailscaleHostForwardOption struct {
	Enabled bool   `proxy:"enabled,omitempty"`
	Target  string `proxy:"target,omitempty"`
	TCP     *bool  `proxy:"tcp,omitempty"`
	UDP     *bool  `proxy:"udp,omitempty"`
}

type tailscaleHostForward struct {
	target netip.Addr
	tcp    bool
	udp    bool
}

func buildTailscaleHostForward(option *TailscaleHostForwardOption) (*tailscaleHostForward, error) {
	if option == nil {
		return nil, nil
	}
	target := option.Target
	if target == "" {
		target = "127.0.0.1"
	}
	addr, err := netip.ParseAddr(target)
	if err != nil || !addr.IsLoopback() || addr.Zone() != "" {
		return nil, fmt.Errorf("tailscale host-forward.target must be a loopback IP address: %q", target)
	}
	if !option.Enabled {
		return nil, nil
	}
	h := &tailscaleHostForward{target: addr.Unmap(), tcp: true, udp: true}
	if option.TCP != nil {
		h.tcp = *option.TCP
	}
	if option.UDP != nil {
		h.udp = *option.UDP
	}
	return h, nil
}

func (t *Tailscale) inboundDestination(network string, dst netip.AddrPort) (netip.AddrPort, bool, bool) {
	var ip4, ip6 netip.Addr
	if t.server != nil {
		ip4, ip6 = t.server.TailscaleIPs()
	}
	return t.forwardDestination(network, dst, ip4, ip6)
}

// forwardDestination checks this node's current addresses before subnet routes,
// including default routes. Disabled host forwarding must not fall through to
// dialing the node's Tailnet IP through the system dialer.
func (t *Tailscale) forwardDestination(network string, dst netip.AddrPort, ip4, ip6 netip.Addr) (target netip.AddrPort, local, ok bool) {
	if network != "tcp" && network != "udp" {
		return netip.AddrPort{}, false, false
	}
	ip := dst.Addr().Unmap()
	if !dst.IsValid() || dst.Port() == 0 || !ip.IsGlobalUnicast() || ip.Zone() != "" {
		return netip.AddrPort{}, false, false
	}
	if ip == ip4.Unmap() || ip == ip6.Unmap() {
		h := t.hostForward
		if h == nil || (network == "tcp" && !h.tcp) || (network == "udp" && !h.udp) {
			return netip.AddrPort{}, false, false
		}
		return netip.AddrPortFrom(h.target, dst.Port()), true, true
	}
	if network == "udp" && !t.option.UDP {
		return netip.AddrPort{}, false, false
	}
	return dst, false, t.advertisesDestination(dst)
}

// Host connections stay in the host network namespace. In particular, they
// must not inherit the outbound's dialer-proxy, interface binding or IP family.
type tailscaleHostDialer struct{}

func (tailscaleHostDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (tailscaleHostDialer) ListenPacket(ctx context.Context, network, _ string, dst netip.AddrPort) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, netip.AddrPortFrom(dst.Addr(), 0).String())
}
