package sing_tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type icmpEchoDestination struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	source, destination netip.Addr
	writer              tun.DirectRouteContext
	probe               func(context.Context, netip.Addr) error
	timeout             time.Duration
	pending             chan struct{}
	mu                  sync.Mutex
	closed              bool
	timer               *time.Timer
}

func newICMPEchoDestination(source, destination netip.Addr, writer tun.DirectRouteContext, timeout time.Duration, probe func(context.Context, netip.Addr) error) *icmpEchoDestination {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &icmpEchoDestination{ctx: ctx, cancel: cancel, source: source.Unmap(), destination: destination.Unmap(), writer: writer, probe: probe, timeout: timeout, pending: make(chan struct{}, 16)}
	d.mu.Lock()
	d.timer = time.AfterFunc(timeout, func() { _ = d.Close() })
	d.mu.Unlock()
	return d
}

func (d *icmpEchoDestination) IsClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

func (d *icmpEchoDestination) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		d.cancel()
		d.timer.Stop()
	}
	return nil
}

func (d *icmpEchoDestination) WritePacket(packet *buf.Buffer) error {
	reply, err := icmpEchoReply(packet.Bytes(), d.source, d.destination)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}
	d.timer.Reset(d.timeout)
	select {
	case d.pending <- struct{}{}:
	default:
		return nil // Bound outstanding probes when a destination is offline.
	}
	go func() {
		defer func() { <-d.pending }()
		ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
		defer cancel()
		if err := d.probe(ctx, d.destination); err != nil {
			log.Debugln("[ICMP] probe %s failed: %v", d.destination, err)
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if !d.closed && ctx.Err() == nil {
			if err := d.writer.WritePacket(reply); err != nil {
				log.Debugln("[ICMP] write reply from %s: %v", d.destination, err)
			}
		}
	}()
	return nil
}

// Validate and copy the request before the TUN releases its buffer. Only echo is
// supported: probing with a separately generated packet cannot preserve MTU,
// TTL, ICMP errors or arbitrary ICMP types. Never acknowledge those as success.
func icmpEchoReply(packet []byte, source, destination netip.Addr) ([]byte, error) {
	invalid := fmt.Errorf("invalid or unsupported ICMP echo request")
	if len(packet) < 20 {
		return nil, invalid
	}
	var offset, length, protocol int
	var want, replyType icmp.Type
	var pseudo []byte
	switch packet[0] >> 4 {
	case 4:
		offset, length, protocol = int(packet[0]&15)*4, int(binary.BigEndian.Uint16(packet[2:4])), 1
		if offset < 20 || length < offset+8 || length > len(packet) || packet[9] != 1 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return nil, invalid
		}
		src, _ := netip.AddrFromSlice(packet[12:16])
		dst, _ := netip.AddrFromSlice(packet[16:20])
		if src != source || dst != destination {
			return nil, invalid
		}
		want, replyType = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
		if icmpInternetChecksum(packet[:offset]) != 0 || icmpInternetChecksum(packet[offset:length]) != 0 {
			return nil, invalid
		}
	case 6:
		if len(packet) < 48 || packet[6] != 58 {
			return nil, invalid
		}
		offset, length, protocol = 40, 40+int(binary.BigEndian.Uint16(packet[4:6])), 58
		if length < 48 || length > len(packet) {
			return nil, invalid
		}
		src, _ := netip.AddrFromSlice(packet[8:24])
		dst, _ := netip.AddrFromSlice(packet[24:40])
		if src != source || dst != destination {
			return nil, invalid
		}
		want, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
		requestPseudo := icmp.IPv6PseudoHeader(source.AsSlice(), destination.AsSlice())
		binary.BigEndian.PutUint32(requestPseudo[32:36], uint32(length-offset))
		if icmpInternetChecksum(append(requestPseudo, packet[offset:length]...)) != 0 {
			return nil, invalid
		}
		pseudo = icmp.IPv6PseudoHeader(destination.AsSlice(), source.AsSlice())
	default:
		return nil, invalid
	}
	m, err := icmp.ParseMessage(protocol, packet[offset:length])
	if err != nil || m.Type != want || m.Code != 0 {
		return nil, invalid
	}
	if _, ok := m.Body.(*icmp.Echo); !ok {
		return nil, invalid
	}
	m.Type = replyType
	payload, err := m.Marshal(pseudo)
	if err != nil {
		return nil, err
	}
	if protocol == 1 {
		reply := make([]byte, 20+len(payload))
		reply[0], reply[8], reply[9] = 0x45, 64, 1
		binary.BigEndian.PutUint16(reply[2:4], uint16(len(reply)))
		copy(reply[12:16], destination.AsSlice())
		copy(reply[16:20], source.AsSlice())
		binary.BigEndian.PutUint16(reply[10:12], icmpInternetChecksum(reply[:20]))
		copy(reply[20:], payload)
		return reply, nil
	}
	reply := make([]byte, 40+len(payload))
	reply[0], reply[6], reply[7] = 0x60, 58, 64
	binary.BigEndian.PutUint16(reply[4:6], uint16(len(payload)))
	copy(reply[8:24], destination.AsSlice())
	copy(reply[24:40], source.AsSlice())
	copy(reply[40:], payload)
	return reply, nil
}

func icmpInternetChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) != 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
