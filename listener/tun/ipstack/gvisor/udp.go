//go:build !no_gvisor

package gvisor

import (
	"net"

	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/adapter"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/option"
	"github.com/Dreamacro/clash/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func withUDPHandler(handle adapter.UDPHandleFunc) option.Option {
	return func(s *stack.Stack) error {
		udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
			var (
				wq waiter.Queue
				id = r.ID()
			)
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				log.Warnln("[STACK] udp forwarder request %s:%d->%s:%d: %s", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort, err)
				return
			}

			conn := &udpConn{
				UDPConn: gonet.NewUDPConn(s, &wq, ep),
				id:      id,
			}
			handle(conn)
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
	payload *buf.Buffer
}

func (c *packet) Data() *buf.Buffer {
	return c.payload
}

// WriteBack write UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, _ net.Addr) (n int, err error) {
	return c.pc.WriteTo(b, c.rAddr)
}

func (c *packet) WritePacket(buffer *buf.Buffer, addr M.Socksaddr) error {
	return common.Error(c.pc.WriteTo(buffer.Bytes(), c.rAddr))
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}
