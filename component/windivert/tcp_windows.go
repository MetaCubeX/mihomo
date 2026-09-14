//go:build windows && (amd64 || 386)

package windivert

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
	M "github.com/metacubex/sing/common/metadata"
	"golang.org/x/sys/windows"
)

type tcpRedirect struct {
	nat       *tun.TCPNat
	listeners []net.Listener
	ports     [2]uint16
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	firewall  string
}

func (t *Tun) startTCP() error {
	r := &tcpRedirect{nat: tun.NewNat(t.ctx, t.options.UDPTimeout), conns: make(map[net.Conn]struct{})}
	t.tcp = r
	program, err := os.Executable()
	if err != nil {
		return err
	}
	rule := fmt.Sprintf("mihomo WFP TCP (%d)", os.Getpid())
	if err = netsh("add", "rule", "name="+rule, "dir=in", "action=allow", "program="+program,
		"protocol=TCP", "profile=any"); err != nil {
		return err
	}
	r.firewall = rule
	for i, network := range []string{"tcp4", "tcp6"} {
		listener, err := net.Listen(network, ":0")
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

func (r *tcpRedirect) redirect(p []byte, info packetInfo) {
	port := r.nat.Lookup(info.source, info.destination)
	// Reflect the outbound packet into a local Windows TCP listener.
	rewriteTCP(p, info, netip.AddrPortFrom(info.destination.Addr(), port),
		netip.AddrPortFrom(info.source.Addr(), r.port(info.source.Addr())))
}

func (r *tcpRedirect) reply(p []byte, info packetInfo) bool {
	session := r.nat.LookupBack(info.destination.Port())
	if session == nil || info.source.Addr() != session.Source.Addr() || info.destination.Addr() != session.Destination.Addr() {
		return false
	}
	rewriteTCP(p, info, session.Destination, session.Source)
	return true
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
		if session == nil || remote.Addr() != session.Destination.Addr() || local.Addr() != session.Source.Addr() {
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
	if r.firewall != "" {
		if err := netsh("delete", "rule", "name="+r.firewall); err != nil {
			log.Warnln("[WFP] remove TCP firewall rule: %s", err)
		}
	}
}

func netsh(args ...string) error {
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(directory, "netsh.exe"), append([]string{"advfirewall", "firewall"}, args...)...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("configure WFP TCP firewall: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
