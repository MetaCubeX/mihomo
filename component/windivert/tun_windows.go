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
	"github.com/metacubex/sing/common/ranges"
)

type Options struct {
	Stack               string
	Handler             tun.Handler
	UDPTimeout          time.Duration
	MTU                 uint32
	IPv6                bool
	HijackDNS           []netip.AddrPort
	RouteAddress        []netip.Prefix
	ExcludeAddress      []netip.Prefix
	IncludeInterface    []string
	ExcludeInterface    []string
	ExcludeSrcPort      []uint16
	ExcludeDstPort      []uint16
	ExcludeSrcPortRange []ranges.Range[uint16]
	ExcludeDstPortRange []ranges.Range[uint16]
}

type Tun struct {
	handle       *handle
	output       [ioParallelism]packetOutput
	batchPool    sync.Pool
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
	socketTables [4]map[flow]uint32
	socketValid  uint8
	interfaceMu  sync.RWMutex
	interfaces   map[netip.Addr]address
	lastSource   netip.Addr
	lastAddress  address
	closeOnce    sync.Once
	packetMu     sync.Mutex
	outputMu     sync.RWMutex
	outputClosed bool
	outputDone   chan struct{}
	running      sync.WaitGroup
}

var active atomic.Pointer[Tun]

func New(options Options) (_ *Tun, err error) {
	for _, prefixes := range [][]netip.Prefix{options.RouteAddress, options.ExcludeAddress} {
		for _, prefix := range prefixes {
			if !prefix.IsValid() || prefix.Addr().Is4In6() {
				return nil, fmt.Errorf("invalid WFP route prefix: %s", prefix)
			}
		}
	}
	for _, target := range options.HijackDNS {
		if !target.IsValid() || target.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid WFP DNS target: %s", target)
		}
	}
	if (options.Stack == "gvisor" || options.Stack == "mixed") && !tun.WithGVisor {
		return nil, fmt.Errorf("gVisor is not included in this build, rebuild with -tags with_gvisor")
	}
	switch options.Stack {
	case "system", "gvisor", "mixed", "mips":
	default:
		return nil, fmt.Errorf("unknown WFP stack: %s", options.Stack)
	}
	t := &Tun{
		options: options, pid: uint32(os.Getpid()),
		tcpFlows:   make(map[flow]uint32),
		interfaces: make(map[netip.Addr]address),
		includeIf:  make(map[uint32]bool), excludeIf: make(map[uint32]bool),
	}
	if !active.CompareAndSwap(nil, t) {
		return nil, fmt.Errorf("only one WFP listener can be active")
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
	t.startOutput()
	switch options.Stack {
	case "system":
		t.deliver = t.deliverUDP
	case "gvisor", "mixed":
		if err = t.startGVisor(); err != nil {
			return nil, err
		}
	case "mips":
		if err = t.startMIPS(); err != nil {
			return nil, err
		}
	}
	if options.Stack == "system" || options.Stack == "mixed" {
		if err = t.startTCP(); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *Tun) Start() error {
	filter, err := t.networkFilter()
	if err != nil {
		return err
	}
	if err := t.handle.start(filter, t.options.IPv6 || len(t.options.HijackDNS) > 0); err != nil {
		return err
	}
	t.running.Add(1)
	go t.readLoop()
	return nil
}

func (t *Tun) capture(info packetInfo) bool {
	if info.protocol == 6 && info.tcpFlags&0x12 != 0x02 {
		_, captured := t.tcpFlows[info.flow]
		if info.tcpFlags&0x04 != 0 {
			delete(t.tcpFlows, info.flow)
		}
		return captured
	}
	// Share the current ownership snapshot within this receive batch.
	index := socketIndex(info.flow)
	entries := t.socketTables[index]
	if t.socketValid&(1<<index) == 0 {
		var err error
		entries, err = t.socketTable(info.flow)
		if err != nil {
			delete(t.tcpFlows, info.flow)
			return false
		}
		t.socketValid |= 1 << index
		if info.protocol == 6 {
			// Reclaim flows that have closed or changed owners.
			for key, previous := range t.tcpFlows {
				if key.source.Addr().Is6() == info.source.Addr().Is6() && entries[key] != previous {
					delete(t.tcpFlows, key)
				}
			}
		}
	}
	owner := socketOwner(entries, info.flow)
	capture := owner != 0 && owner != t.pid
	if info.protocol == 6 {
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

	type receivedBatch struct {
		packets   []byte
		addresses []address
		n, count  int
		err       error
	}
	free := make(chan *receivedBatch, 2)
	ready := make(chan *receivedBatch)
	for i := 0; i < 2; i++ {
		free <- &receivedBatch{packets: make([]byte, batchBytes), addresses: make([]address, batchSize)}
	}
	t.running.Add(1)
	go func() {
		defer t.running.Done()
		for {
			var b *receivedBatch
			select {
			case b = <-free:
			case <-t.ctx.Done():
				return
			}
			b.n, b.count, b.err = t.handle.recvBatch(b.packets, b.addresses)
			select {
			case ready <- b:
			case <-t.ctx.Done():
				return
			}
			if b.err != nil {
				return
			}
		}
	}()
	batch := newPacketWriter(t)
	defer batch.release()
	for {
		var received *receivedBatch
		select {
		case received = <-ready:
		case <-t.ctx.Done():
			return
		}
		p, addresses := received.packets, received.addresses
		n, count, err := received.n, received.count, received.err
		if err != nil {
			if t.ctx.Err() == nil {
				t.close(fmt.Errorf("receive: %w", err))
			}
			return
		}
		t.socketValid = 0
		read := 0
		for i := 0; i < count; i++ {
			size := packetSize(p[read:n])
			if size == 0 {
				t.close(fmt.Errorf("invalid packet in receive batch"))
				return
			}
			packet := p[read : read+size]
			t.packetMu.Lock()
			if t.ctx.Err() != nil {
				t.packetMu.Unlock()
				return
			}
			addr, inject := t.processPacket(packet, addresses[i])
			t.packetMu.Unlock()
			if inject {
				batch.append(addr, packetKey(packet), packet)
			}
			read += size
		}
		batch.flush()
		free <- received
	}
}

// processPacket returns the address and whether the packet needs reinjection.
func (t *Tun) processPacket(p []byte, addr address) (address, bool) {
	info, ok := parsePacket(p)
	if ok && t.tcp != nil && t.tcp.isReply(info) {
		// Expired or unsolicited relay connections must not escape to the network.
		return t.tcp.reply(p, info)
	}
	if !ok || !t.capture(info) {
		return addr, true
	}
	if t.options.Stack == "mips" {
		completeChecksums(p, info, addr.Flags)
	}
	// Replies are inbound on this interface; zero checksum flags request recalculation.
	addr = address{IfIdx: addr.IfIdx, SubIfIdx: addr.SubIfIdx}
	if info.protocol == 6 && t.tcp != nil {
		return t.tcp.redirect(p, info, addr)
	}
	if t.options.Stack != "system" && (t.lastSource != info.source.Addr() || t.lastAddress != addr) {
		t.interfaceMu.Lock()
		t.interfaces[info.source.Addr()] = addr
		t.interfaceMu.Unlock()
		t.lastSource, t.lastAddress = info.source.Addr(), addr
	}
	t.deliver(p, info, addr)
	return address{}, false
}

func (t *Tun) responseInterface(destination netip.Addr) (address, bool) {
	t.interfaceMu.RLock()
	addr, ok := t.interfaces[destination]
	t.interfaceMu.RUnlock()
	return addr, ok
}

func (t *Tun) close(err error) {
	t.closeOnce.Do(func() {
		if err != nil {
			log.Errorln("[WFP] %s", err)
		}
		t.cancel()
		// Cancellation unblocks producers; stop senders only after every enqueue
		// has either completed or released its buffers.
		t.outputMu.Lock()
		t.outputClosed = true
		if t.outputDone != nil {
			close(t.outputDone)
		}
		t.outputMu.Unlock()
		t.packetMu.Lock()
		defer t.packetMu.Unlock()
		if t.tcp != nil {
			t.tcp.close()
		}
		if t.handle != nil {
			t.handle.close()
		}
		if t.closeStack != nil {
			t.closeStack()
		}
		go func() { t.running.Wait(); active.CompareAndSwap(t, nil) }()
	})
}

func (t *Tun) Close() error {
	t.close(nil)
	t.running.Wait()
	active.CompareAndSwap(t, nil)
	return nil
}
