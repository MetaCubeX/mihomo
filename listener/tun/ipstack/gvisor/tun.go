package gvisor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/listener/tun/dev"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID tcpip.NICID = 1

type gvisorAdapter struct {
	device    dev.TunDevice
	ipstack   *stack.Stack
	dnsServer *DNSServer
	udpIn     chan<- *inbound.PacketAdapter

	stackName string
	autoRoute bool
	linkCache *channel.Endpoint
	wg        sync.WaitGroup // wait for goroutines to stop

	writeHandle *channel.NotificationHandle
}

// NewAdapter GvisorAdapter create GvisorAdapter
func NewAdapter(device dev.TunDevice, conf config.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.TunAdapter, error) {
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	adapter := &gvisorAdapter{
		device:    device,
		ipstack:   ipstack,
		udpIn:     udpIn,
		stackName: conf.Stack,
		autoRoute: conf.AutoRoute,
	}

	linkEP, err := adapter.AsLinkEndpoint()
	if err != nil {
		return nil, fmt.Errorf("unable to create virtual endpoint: %v", err)
	}

	if err := ipstack.CreateNIC(nicID, linkEP); err != nil {
		return nil, fmt.Errorf("fail to create NIC in ipstack: %v", err)
	}

	ipstack.SetPromiscuousMode(nicID, true) // Accept all the traffice from this NIC
	ipstack.SetSpoofing(nicID, true)        // Otherwise our TCP connection can not find the route backward

	// Add route for ipv4 & ipv6
	// So FindRoute will return correct route to tun NIC
	subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	ipstack.AddRoute(tcpip.Route{Destination: subnet, Gateway: "", NIC: nicID})
	subnet, _ = tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 16)), tcpip.AddressMask(strings.Repeat("\x00", 16)))
	ipstack.AddRoute(tcpip.Route{Destination: subnet, Gateway: "", NIC: nicID})

	// TCP handler
	// maximum number of half-open tcp connection set to 1024
	// receive buffer size set to 20k
	tcpFwd := tcp.NewForwarder(ipstack, pool.RelayBufferSize, 1024, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Warnln("Can't create TCP Endpoint in ipstack: %v", err)
			r.Complete(true)
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)

		// if the endpoint is not in connected state, conn.RemoteAddr() will return nil
		// this protection may be not enough, but will help us debug the panic
		if conn.RemoteAddr() == nil {
			log.Warnln("TCP endpoint is not connected, current state: %v", tcp.EndpointState(ep.State()))
			conn.Close()
			return
		}

		target := getAddr(ep.Info().(*stack.TransportEndpointInfo).ID)
		tcpIn <- inbound.NewSocket(target, conn, C.TUN)
	})
	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP handler
	ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, adapter.udpHandlePacket)

	if resolver.DefaultResolver != nil {
		err = adapter.ReCreateDNSServer(resolver.DefaultResolver.(*dns.Resolver), resolver.DefaultHostMapper.(*dns.ResolverEnhancer), conf.DnsHijack)
		if err != nil {
			return nil, err
		}
	}

	return adapter, nil
}

func (t *gvisorAdapter) Stack() string {
	return t.stackName
}

func (t *gvisorAdapter) AutoRoute() bool {
	return t.autoRoute
}

// Close close the TunAdapter
func (t *gvisorAdapter) Close() {
	t.StopDNSServer()
	if t.ipstack != nil {
		t.ipstack.Close()
	}
	if t.device != nil {
		_ = t.device.Close()
	}
}

func (t *gvisorAdapter) udpHandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	// ref: gvisor pkg/tcpip/transport/udp/endpoint.go HandlePacket
	hdr := header.UDP(pkt.TransportHeader().View())
	if int(hdr.Length()) > pkt.Data().Size()+header.UDPMinimumSize {
		// Malformed packet.
		t.ipstack.Stats().UDP.MalformedPacketsReceived.Increment()
		return true
	}

	target := getAddr(id)

	packet := &fakeConn{
		id:      id,
		pkt:     pkt,
		s:       t.ipstack,
		payload: pkt.Data().AsRange().ToOwnedView(),
	}

	select {
	case t.udpIn <- inbound.NewPacket(target, packet, C.TUN):
	default:
	}

	return true
}

// Wait wait goroutines to exit
func (t *gvisorAdapter) Wait() {
	t.wg.Wait()
}

func (t *gvisorAdapter) AsLinkEndpoint() (result stack.LinkEndpoint, err error) {
	if t.linkCache != nil {
		return t.linkCache, nil
	}

	mtu, err := t.device.MTU()
	if err != nil {
		return nil, errors.New("unable to get device mtu")
	}

	linkEP := channel.New(512, uint32(mtu), "")

	// start Read loop. read ip packet from tun and write it to ipstack
	t.wg.Add(1)
	go func() {
		for !t.device.IsClose() {
			packet := make([]byte, mtu)
			n, err := t.device.Read(packet)
			if err != nil && !t.device.IsClose() {
				log.Errorln("can not read from tun: %v", err)
				continue
			}
			var p tcpip.NetworkProtocolNumber
			switch header.IPVersion(packet) {
			case header.IPv4Version:
				p = header.IPv4ProtocolNumber
			case header.IPv6Version:
				p = header.IPv6ProtocolNumber
			}
			if linkEP.IsAttached() {
				linkEP.InjectInbound(p, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: buffer.View(packet[:n]).ToVectorisedView(),
				}))
			} else {
				log.Debugln("received packet from tun when %s is not attached to any dispatcher.", t.device.Name())
			}
		}
		t.wg.Done()
		t.Close()
		log.Debugln("%v stop read loop", t.device.Name())
	}()

	// start write notification
	t.writeHandle = linkEP.AddNotify(t)
	t.linkCache = linkEP
	return t.linkCache, nil
}

// WriteNotify implements channel.Notification.WriteNotify.
func (t *gvisorAdapter) WriteNotify() {
	packetBuffer := t.linkCache.Read()
	if packetBuffer != nil {
		var vv buffer.VectorisedView
		// Append upper headers.
		vv.AppendView(packetBuffer.NetworkHeader().View())
		vv.AppendView(packetBuffer.TransportHeader().View())
		// Append data payload.
		vv.Append(packetBuffer.Data().ExtractVV())

		_, err := t.device.Write(vv.ToView())
		if err != nil && !t.device.IsClose() {
			log.Errorln("can not write to tun: %v", err)
		}
	}
}

func getAddr(id stack.TransportEndpointID) socks5.Addr {
	ipv4 := id.LocalAddress.To4()

	// get the big-endian binary represent of port
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, id.LocalPort)

	if ipv4 != "" {
		addr := make([]byte, 1+net.IPv4len+2)
		addr[0] = socks5.AtypIPv4
		copy(addr[1:1+net.IPv4len], []byte(ipv4))
		addr[1+net.IPv4len], addr[1+net.IPv4len+1] = port[0], port[1]
		return addr
	} else {
		addr := make([]byte, 1+net.IPv6len+2)
		addr[0] = socks5.AtypIPv6
		copy(addr[1:1+net.IPv6len], []byte(id.LocalAddress))
		addr[1+net.IPv6len], addr[1+net.IPv6len+1] = port[0], port[1]
		return addr
	}
}
