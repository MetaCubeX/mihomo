package nat

import (
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync"

	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars/tcpip"
)

type call struct {
	cond        *sync.Cond
	buf         []byte
	n           int
	source      netip.AddrPort
	destination netip.AddrPort
}

type UDP struct {
	closed    bool
	device    io.Writer
	queueLock sync.Mutex
	queue     []*call
	bufLock   sync.Mutex
	buf       []byte
}

func (u *UDP) ReadFrom(buf []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	u.queueLock.Lock()
	defer u.queueLock.Unlock()

	for !u.closed {
		c := &call{
			cond:        sync.NewCond(&u.queueLock),
			buf:         buf,
			n:           -1,
			source:      netip.AddrPort{},
			destination: netip.AddrPort{},
		}

		u.queue = append(u.queue, c)

		c.cond.Wait()

		if c.n >= 0 {
			return c.n, c.source, c.destination, nil
		}
	}

	return -1, netip.AddrPort{}, netip.AddrPort{}, net.ErrClosed
}

func (u *UDP) WriteTo(buf []byte, local netip.AddrPort, remote netip.AddrPort) (int, error) {
	if u.closed {
		return 0, net.ErrClosed
	}

	u.bufLock.Lock()
	defer u.bufLock.Unlock()

	if len(buf) > 0xffff {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	if !local.Addr().Is4() || !remote.Addr().Is4() {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	tcpip.SetIPv4(u.buf[:])

	ip := tcpip.IPv4Packet(u.buf[:])
	ip.SetHeaderLen(tcpip.IPv4HeaderSize)
	ip.SetTotalLength(tcpip.IPv4HeaderSize + tcpip.UDPHeaderSize + uint16(len(buf)))
	ip.SetTypeOfService(0)
	ip.SetIdentification(uint16(rand.Uint32()))
	ip.SetFragmentOffset(0)
	ip.SetTimeToLive(64)
	ip.SetProtocol(tcpip.UDP)
	ip.SetSourceIP(local.Addr())
	ip.SetDestinationIP(remote.Addr())

	udp := tcpip.UDPPacket(ip.Payload())
	udp.SetLength(tcpip.UDPHeaderSize + uint16(len(buf)))
	udp.SetSourcePort(local.Port())
	udp.SetDestinationPort(remote.Port())
	copy(udp.Payload(), buf)

	ip.ResetChecksum()
	udp.ResetChecksum(ip.PseudoSum())

	return u.device.Write(u.buf[:ip.TotalLen()])
}

func (u *UDP) Close() error {
	u.queueLock.Lock()
	defer u.queueLock.Unlock()

	u.closed = true

	for _, c := range u.queue {
		c.cond.Signal()
	}

	return nil
}

func (u *UDP) handleUDPPacket(ip tcpip.IP, pkt tcpip.UDPPacket) {
	var c *call

	u.queueLock.Lock()

	if len(u.queue) > 0 {
		idx := len(u.queue) - 1
		c = u.queue[idx]
		u.queue = u.queue[:idx]
	}

	u.queueLock.Unlock()

	if c != nil {
		c.source = netip.AddrPortFrom(ip.SourceIP(), pkt.SourcePort())
		c.destination = netip.AddrPortFrom(ip.DestinationIP(), pkt.DestinationPort())
		c.n = copy(c.buf, pkt.Payload())
		c.cond.Signal()
	}
}
