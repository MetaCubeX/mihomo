//go:build windows && (amd64 || 386)

package windivert

import (
	"net"
	"net/netip"
	"sync"

	tun "github.com/metacubex/sing-tun"
	M "github.com/metacubex/sing/common/metadata"
)

type tcpRedirect struct {
	nat       *tun.TCPNat
	listeners []net.Listener
	ports     [2]uint16
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	// Only the packet reader accesses routes.
	routes map[uint16]address
}

func (t *Tun) startTCP() error {
	r := &tcpRedirect{nat: tun.NewNat(t.ctx, t.options.UDPTimeout), conns: make(map[net.Conn]struct{}), routes: make(map[uint16]address)}
	t.tcp = r
	for i, network := range []string{"tcp4", "tcp6"} {
		if i == 1 && !t.options.IPv6 && len(t.options.HijackDNS) == 0 {
			continue
		}
		bind := "127.0.0.1:0"
		if i == 1 {
			bind = "[::1]:0"
		}
		listener, err := net.Listen(network, bind)
		if err != nil {
			return err
		}
		r.listeners = append(r.listeners, listener)
		r.ports[i] = listener.Addr().(*net.TCPAddr).AddrPort().Port()
	}
	t.running.Add(len(r.listeners))
	for _, listener := range r.listeners {
		go r.accept(t, listener)
	}
	return nil
}

func (r *tcpRedirect) port(ip netip.Addr) uint16 {
	if ip.Is6() {
		return r.ports[1]
	}
	return r.ports[0]
}

func relayPeer(ip netip.Addr) netip.Addr {
	if ip.Is6() {
		return netip.IPv6Loopback()
	}
	return netip.AddrFrom4([4]byte{127, 0, 0, 2})
}

func relayLocal(ip netip.Addr) netip.Addr {
	if ip.Is6() {
		return netip.IPv6Loopback()
	}
	return netip.AddrFrom4([4]byte{127, 0, 0, 1})
}

func (r *tcpRedirect) isReply(info packetInfo) bool {
	return info.protocol == 6 && info.source.Port() == r.port(info.source.Addr()) &&
		info.source.Addr() == relayLocal(info.source.Addr()) && info.destination.Addr() == relayPeer(info.source.Addr())
}

func (r *tcpRedirect) redirect(p []byte, info packetInfo, addr address) (address, bool) {
	port, err := r.nat.Lookup(info.source, info.destination)
	if err != nil {
		return address{}, false
	}
	r.routes[port] = addr
	// Relay both endpoints over loopback.
	rewriteTCP(p, info, netip.AddrPortFrom(relayPeer(info.source.Addr()), port),
		netip.AddrPortFrom(relayLocal(info.source.Addr()), r.port(info.source.Addr())))
	return address{Flags: flagOutbound}, true
}

func (r *tcpRedirect) reply(p []byte, info packetInfo) (address, bool) {
	session := r.nat.LookupBack(info.destination.Port())
	addr, ok := r.routes[info.destination.Port()]
	if session == nil || !ok || session.Source.Addr().Is6() != info.source.Addr().Is6() {
		return address{}, false
	}
	rewriteTCP(p, info, session.Destination, session.Source)
	return addr, true
}

func (r *tcpRedirect) accept(t *Tun, listener net.Listener) {
	defer t.running.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		remote := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		session := r.nat.LookupBack(remote.Port())
		if session == nil || remote.Addr() != relayPeer(session.Source.Addr()) || local.Addr() != relayLocal(session.Source.Addr()) {
			conn.Close()
			continue
		}
		r.mu.Lock()
		if t.ctx.Err() != nil {
			r.mu.Unlock()
			conn.Close()
			return
		}
		r.conns[conn] = struct{}{}
		t.running.Add(1)
		r.mu.Unlock()
		go func() {
			defer t.running.Done()
			defer func() {
				conn.Close()
				r.mu.Lock()
				delete(r.conns, conn)
				r.mu.Unlock()
			}()
			t.options.Handler.NewConnection(t.ctx, conn, M.Metadata{
				Source: M.SocksaddrFromNetIP(session.Source), Destination: M.SocksaddrFromNetIP(session.Destination),
			})
		}()
	}
}

func (r *tcpRedirect) close() {
	for _, listener := range r.listeners {
		listener.Close()
	}
	r.mu.Lock()
	for conn := range r.conns {
		conn.Close()
	}
	r.mu.Unlock()
}
