//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"net"
	"net/netip"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tailscale/types/nettype"
)

// StartBackground publishes (or explicitly clears) routes even if no outbound
// connection uses this adapter. Constructors remain free of network side effects.
func (t *Tailscale) StartBackground() {
	if t.option.AdvertiseRoutes == nil {
		return
	}
	t.backgroundOnce.Do(func() {
		go func() {
			if err := t.start(); err != nil && t.ctx.Err() == nil {
				log.Warnln("[Tailscale](%s) start route publisher failed: %v", t.Name(), err)
			}
		}()
	})
}

func (t *Tailscale) advertisesDestination(dst netip.AddrPort) bool {
	ip := dst.Addr().Unmap()
	if dst.Port() == 0 || !ip.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range t.advertisedRoutes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (t *Tailscale) tcpHandlerForAdvertisedRoute(_, dst netip.AddrPort) (func(net.Conn), bool) {
	if !t.advertisesDestination(dst) {
		return nil, false
	}
	return func(conn net.Conn) { t.forwardAdvertisedTCP(conn, dst) }, true
}

func (t *Tailscale) udpHandlerForAdvertisedRoute(_, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
	if !t.option.UDP || !t.advertisesDestination(dst) {
		return nil, false
	}
	return func(conn nettype.ConnPacketConn) { t.forwardAdvertisedUDP(conn, dst) }, true
}

func (t *Tailscale) forwardAdvertisedTCP(client net.Conn, dst netip.AddrPort) {
	defer client.Close()
	defer N.SetupContextForConn(t.ctx, client)(nil)
	ctx, cancel := context.WithTimeout(t.ctx, C.DefaultTCPTimeout)
	backend, err := t.dialer.DialContext(ctx, "tcp", dst.String())
	cancel()
	if err != nil {
		log.Debugln("[Tailscale](%s) forward TCP to %s: %v", t.Name(), dst, err)
		return
	}
	defer backend.Close()
	_ = N.RelayContext(t.ctx, client, backend)
}

func (t *Tailscale) forwardAdvertisedUDP(client net.Conn, dst netip.AddrPort) {
	defer client.Close()
	defer N.SetupContextForConn(t.ctx, client)(nil)
	dialCtx, dialCancel := context.WithTimeout(t.ctx, C.DefaultTCPTimeout)
	network := "udp4"
	if dst.Addr().Is6() {
		network = "udp6"
	}
	backend, err := t.dialer.ListenPacket(dialCtx, network, "", dst)
	dialCancel()
	if err != nil {
		log.Debugln("[Tailscale](%s) forward UDP to %s: %v", t.Name(), dst, err)
		return
	}
	defer backend.Close()
	tailscaleRelayUDP(t.ctx, client, backend, dst, C.DefaultUDPTimeout)
}

// A UDP flow keeps datagram boundaries (including empty packets), accepts replies
// only from its destination, and releases both sockets on idle, error or shutdown.
func tailscaleRelayUDP(parent context.Context, client net.Conn, backend net.PacketConn, dst netip.AddrPort, idle time.Duration) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = backend.Close()
	})
	defer stop()
	timer := time.AfterFunc(idle, cancel)
	defer timer.Stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			from, err := netip.ParseAddrPort(addr.String())
			if err != nil || from.Port() != dst.Port() || from.Addr().Unmap() != dst.Addr().Unmap() {
				continue
			}
			if _, err = client.Write(buf[:n]); err != nil {
				return
			}
			timer.Reset(idle)
		}
	}()
	buf := make([]byte, 65535)
	remote := net.UDPAddrFromAddrPort(dst)
	for {
		n, err := client.Read(buf)
		if err != nil {
			break
		}
		if _, err = backend.WriteTo(buf[:n], remote); err != nil {
			break
		}
		timer.Reset(idle)
	}
	cancel()
	<-done
}
