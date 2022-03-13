package gvisor

import (
	"fmt"
	"github.com/Dreamacro/clash/log"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"net"

	"github.com/Dreamacro/clash/component/resolver"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type fakeConn struct {
	id      stack.TransportEndpointID // The endpoint of incomming packet, it's remote address is the source address it sent from
	pkt     *stack.PacketBuffer       // The original packet comming from tun
	s       *stack.Stack
	payload []byte
	fakeip  *bool
}

func (c *fakeConn) Data() []byte {
	return c.payload
}

func (c *fakeConn) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	v := buffer.View(b)
	data := v.ToVectorisedView()

	var localAddress tcpip.Address
	var localPort uint16
	// if addr is not provided, write back use original dst Addr as src Addr
	if c.FakeIP() || addr == nil {
		localAddress = c.id.LocalAddress
		localPort = c.id.LocalPort
	} else {
		udpaddr, _ := addr.(*net.UDPAddr)
		localAddress = tcpip.Address(udpaddr.IP)
		localPort = uint16(udpaddr.Port)
	}

	if !c.pkt.NetworkHeader().View().IsEmpty() &&
		(c.pkt.NetworkProtocolNumber == ipv4.ProtocolNumber ||
			c.pkt.NetworkProtocolNumber == ipv6.ProtocolNumber) {
		r, _ := c.s.FindRoute(c.pkt.NICID, localAddress, c.id.RemoteAddress, c.pkt.NetworkProtocolNumber, false /* multicastLoop */)
		return writeUDP(r, data, localPort, c.id.RemotePort)
	} else {
		log.Debugln("the network protocl[%d] is not available", c.pkt.NetworkProtocolNumber)
		return 0, fmt.Errorf("the network protocl[%d] is not available", c.pkt.NetworkProtocolNumber)
	}
}

func (c *fakeConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(c.id.RemoteAddress), Port: int(c.id.RemotePort)}
}

func (c *fakeConn) Close() error {
	return nil
}

func (c *fakeConn) Drop() {
}

func (c *fakeConn) FakeIP() bool {
	if c.fakeip != nil {
		return *c.fakeip
	}
	fakeip := resolver.IsFakeIP(net.IP(c.id.LocalAddress.To4()))
	c.fakeip = &fakeip
	return fakeip
}

func writeUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16) (int, error) {
	const protocol = udp.ProtocolNumber
	// Allocate a buffer for the UDP header.

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(r.MaxHeaderLength()),
		Data:               data,
	})

	// Initialize the header.
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))

	length := uint16(pkt.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: localPort,
		DstPort: remotePort,
		Length:  length,
	})

	// Set the checksum field unless TX checksum offload is enabled.
	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	if r.RequiresTXTransportChecksum() {
		xsum := r.PseudoHeaderChecksum(protocol, length)
		for _, v := range data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		udp.SetChecksum(^udp.CalculateChecksum(xsum))
	}

	ttl := r.DefaultTTL()

	if err := r.WritePacket(stack.NetworkHeaderParams{Protocol: protocol, TTL: ttl, TOS: 0 /* default */}, pkt); err != nil {
		r.Stats().UDP.PacketSendErrors.Increment()
		return 0, fmt.Errorf("%v", err)
	}

	// Track count of packets sent.
	r.Stats().UDP.PacketsSent.Increment()
	return data.Size(), nil
}
