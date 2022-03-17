package gvisor

import (
	"net"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/adapter"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func withUDPHandler() Option {
	return func(s *gvStack) error {
		udpForwarder := udp.NewForwarder(s.Stack, func(r *udp.ForwarderRequest) {
			var wq waiter.Queue
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				// TODO: handler errors in the future.
				return
			}

			conn := &udpConn{
				UDPConn: gonet.NewUDPConn(s.Stack, &wq, ep),
				id:      r.ID(),
			}
			s.handler.HandleUDPConn(conn)
		})
		s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
		return nil
	}
}

type udpConn struct {
	*gonet.UDPConn
	id stack.TransportEndpointID
}

func (c *udpConn) ID() *stack.TransportEndpointID {
	return &c.id
}

type packet struct {
	pc      adapter.UDPConn
	rAddr   net.Addr
	payload []byte
}

func (c *packet) Data() []byte {
	return c.payload
}

// WriteBack write UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	return c.pc.WriteTo(b, c.rAddr)
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}

func (c *packet) Drop() {
	pool.Put(c.payload)
}
