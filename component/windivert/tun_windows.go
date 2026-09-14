//go:build windows && (amd64 || 386)

package windivert

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
	"golang.org/x/exp/slices"
)

type Options struct {
	Stack            string
	Handler          tun.Handler
	UDPTimeout       time.Duration
	MTU              uint32
	IPv6             bool
	HijackDNS        func(netip.AddrPort) bool
	RouteAddress     []netip.Prefix
	ExcludeAddress   []netip.Prefix
	IncludeInterface []string
	ExcludeInterface []string
	ExcludeSrcPort   []uint16
	ExcludeDstPort   []uint16
}

type Tun struct {
	handle       *handle
	ctx          context.Context
	cancel       context.CancelFunc
	tcp          *tcpRedirect
	deliver      func([]byte, packetInfo, address)
	closeStack   func()
	options      Options
	pid          uint32
	includeIf    map[uint32]bool
	excludeIf    map[uint32]bool
	tcpFlows     map[flow]uint32
	socketBuffer []byte
	closeOnce    sync.Once
	running      sync.WaitGroup
}

var active atomic.Bool

func New(options Options) (_ *Tun, err error) {
	if !active.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("only one WFP listener can be active")
	}
	t := &Tun{
		options: options, pid: uint32(os.Getpid()),
		tcpFlows:  make(map[flow]uint32),
		includeIf: make(map[uint32]bool), excludeIf: make(map[uint32]bool),
	}
	t.ctx, t.cancel = context.WithCancel(context.Background())
	defer func() {
		if err != nil {
			t.Close()
		}
	}()
	for _, entry := range []struct {
		names   []string
		indexes map[uint32]bool
	}{
		{options.IncludeInterface, t.includeIf}, {options.ExcludeInterface, t.excludeIf},
	} {
		for _, name := range entry.names {
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return nil, err
			}
			entry.indexes[uint32(iface.Index)] = true
		}
	}
	t.handle, err = openHandle()
	if err != nil {
		return nil, err
	}
	switch options.Stack {
	case "system":
		t.deliver = t.deliverUDP
	case "gvisor", "mixed":
		if err = t.startGVisor(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown WFP stack: %s", options.Stack)
	}
	if options.Stack != "gvisor" {
		if err = t.startTCP(); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *Tun) Start() error {
	if err := t.handle.start(); err != nil {
		return err
	}
	t.running.Add(1)
	go t.readLoop()
	return nil
}

func (t *Tun) selected(info packetInfo, addr address) bool {
	dst := info.destination.Addr()
	if !dst.IsGlobalUnicast() || t.excludeIf[addr.IfIdx] || (len(t.includeIf) > 0 && !t.includeIf[addr.IfIdx]) {
		return false
	}
	// DNS transport can use IPv6 even when IPv6 proxy traffic is disabled.
	if !t.options.IPv6 && dst.Is6() && (t.options.HijackDNS == nil || !t.options.HijackDNS(info.destination)) {
		return false
	}
	if len(t.options.RouteAddress) > 0 && !containsAddress(t.options.RouteAddress, dst) {
		return false
	}
	if containsAddress(t.options.ExcludeAddress, dst) {
		return false
	}
	return !slices.Contains(t.options.ExcludeSrcPort, info.source.Port()) &&
		!slices.Contains(t.options.ExcludeDstPort, info.destination.Port())
}

func containsAddress(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (t *Tun) capture(info packetInfo) bool {
	if info.protocol == 6 && info.tcpFlags&0x12 != 0x02 {
		_, captured := t.tcpFlows[info.flow]
		if info.tcpFlags&0x04 != 0 {
			delete(t.tcpFlows, info.flow)
		}
		return captured
	}
	// Resolve SYNs and UDP packets against current ownership to handle port reuse.
	entries, err := t.socketTable(info.flow)
	owner := entries[info.flow]
	capture := err == nil && owner != 0 && owner != t.pid
	if info.protocol == 6 {
		// Reclaim flows that have closed or changed owners.
		if err == nil {
			for key, previous := range t.tcpFlows {
				if key.source.Addr().Is6() == info.source.Addr().Is6() && entries[key] != previous {
					delete(t.tcpFlows, key)
				}
			}
		}
		if capture {
			t.tcpFlows[info.flow] = owner
		} else {
			delete(t.tcpFlows, info.flow)
		}
	}
	return capture
}

func (t *Tun) readLoop() {
	defer t.running.Done()
	p := make([]byte, 65575) // IPv6 header plus its maximum non-jumbo payload.
	for {
		var addr address
		n, err := t.handle.recv(p, &addr)
		if err != nil {
			if t.ctx.Err() == nil {
				t.close(fmt.Errorf("receive: %w", err))
			}
			return
		}
		addr, inject := t.processPacket(p[:n], addr)
		if inject {
			if _, err = t.handle.send(p[:n], &addr); err != nil && t.ctx.Err() == nil {
				log.Warnln("[WFP] inject: packet dropped: %s", err)
			}
		}
	}
}

// processPacket returns the address and whether the packet needs reinjection.
func (t *Tun) processPacket(p []byte, addr address) (address, bool) {
	info, ok := parsePacket(p)
	if ok && t.tcp != nil && info.protocol == 6 && info.source.Port() == t.tcp.port(info.source.Addr()) {
		// Expired or unsolicited relay connections must not escape to the network.
		return address{IfIdx: addr.IfIdx, SubIfIdx: addr.SubIfIdx}, t.tcp.reply(p, info)
	}
	if !ok || !t.selected(info, addr) || !t.capture(info) {
		return addr, true
	}
	// Replies are inbound on this interface; zero checksum flags request recalculation.
	addr = address{IfIdx: addr.IfIdx, SubIfIdx: addr.SubIfIdx}
	if info.protocol == 6 && t.tcp != nil {
		t.tcp.redirect(p, info)
		return addr, true
	}
	t.deliver(p, info, addr)
	return address{}, false
}

func (t *Tun) close(err error) {
	t.closeOnce.Do(func() {
		if err != nil {
			log.Errorln("[WFP] %s", err)
		}
		t.cancel()
		if t.tcp != nil {
			t.tcp.close()
		}
		if t.handle != nil {
			t.handle.close()
		}
		if t.closeStack != nil {
			t.closeStack()
		}
		active.Store(false)
	})
}

func (t *Tun) Close() error {
	t.close(nil)
	t.running.Wait()
	return nil
}
