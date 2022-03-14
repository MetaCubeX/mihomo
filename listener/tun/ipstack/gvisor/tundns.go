package gvisor

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"net"

	Common "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/log"
	D "github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var (
	ipv4Zero = tcpip.Address(net.IPv4zero.To4())
	ipv6Zero = tcpip.Address(net.IPv6zero.To16())
)

type ListenerWrap struct {
	net.Listener
	listener net.Listener
}

func (l *ListenerWrap) Accept() (conn net.Conn, err error) {
	conn, err = l.listener.Accept()
	log.Debugln("[DNS] hijack tcp:%s", l.Addr())
	return
}

func (l *ListenerWrap) Close() error {
	return l.listener.Close()
}

func (l *ListenerWrap) Addr() net.Addr {
	return l.listener.Addr()
}

// DNSServer is DNS Server listening on tun devcice
type DNSServer struct {
	dnsServers     []*dns.Server
	tcpListeners   []net.Listener
	resolver       *dns.Resolver
	stack          *stack.Stack
	udpEndpoints   []*dnsEndpoint
	udpEndpointIDs []*stack.TransportEndpointID
	tcpip.NICID
}

// dnsEndpoint is a TransportEndpoint that will register to stack
type dnsEndpoint struct {
	stack.TransportEndpoint
	stack    *stack.Stack
	uniqueID uint64
	server   *dns.Server
}

// Keep track of the source of DNS request
type dnsResponseWriter struct {
	s   *stack.Stack
	pkt *stack.PacketBuffer // The request packet
	id  stack.TransportEndpointID
}

func (e *dnsEndpoint) UniqueID() uint64 {
	return e.uniqueID
}

func (e *dnsEndpoint) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	hdr := header.UDP(pkt.TransportHeader().View())
	if int(hdr.Length()) > pkt.Data().Size()+header.UDPMinimumSize {
		// Malformed packet.
		e.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		return
	}

	// server DNS
	var msg D.Msg
	msg.Unpack(pkt.Data().AsRange().ToOwnedView())
	writer := dnsResponseWriter{s: e.stack, pkt: pkt, id: id}
	log.Debugln("[DNS] hijack udp:%s:%d from %s:%d", id.LocalAddress.String(), id.LocalPort,
		id.RemoteAddress.String(), id.RemotePort)
	go e.server.ServeDNS(&writer, &msg)
}

func (e *dnsEndpoint) Close() {
}

func (e *dnsEndpoint) Wait() {
}

func (e *dnsEndpoint) HandleError(transErr stack.TransportError, pkt *stack.PacketBuffer) {
	log.Warnln("DNS endpoint get a transport error: %v", transErr)
	log.Debugln("DNS endpoint transport error packet : %v", pkt)
}

// Abort implements stack.TransportEndpoint.Abort.
func (e *dnsEndpoint) Abort() {
	e.Close()
}

func (w *dnsResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(w.id.LocalAddress), Port: int(w.id.LocalPort)}
}

func (w *dnsResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(w.id.RemoteAddress), Port: int(w.id.RemotePort)}
}

func (w *dnsResponseWriter) WriteMsg(msg *D.Msg) error {
	b, err := msg.Pack()
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func (w *dnsResponseWriter) TsigStatus() error {
	// Unsupported
	return nil
}

func (w *dnsResponseWriter) TsigTimersOnly(bool) {
	// Unsupported
}

func (w *dnsResponseWriter) Hijack() {
	// Unsupported
}

func (w *dnsResponseWriter) Write(b []byte) (int, error) {
	v := buffer.NewView(len(b))
	copy(v, b)
	data := v.ToVectorisedView()

	// w.id.LocalAddress is the source ip of DNS response
	if !w.pkt.NetworkHeader().View().IsEmpty() &&
		(w.pkt.NetworkProtocolNumber == ipv4.ProtocolNumber ||
			w.pkt.NetworkProtocolNumber == ipv6.ProtocolNumber) {
		r, _ := w.s.FindRoute(w.pkt.NICID, w.id.LocalAddress, w.id.RemoteAddress, w.pkt.NetworkProtocolNumber, false /* multicastLoop */)
		return writeUDP(r, data, w.id.LocalPort, w.id.RemotePort)
	} else {
		log.Debugln("the network protocl[%d] is not available", w.pkt.NetworkProtocolNumber)
		return 0, fmt.Errorf("the network protocl[%d] is not available", w.pkt.NetworkProtocolNumber)
	}
}

func (w *dnsResponseWriter) Close() error {
	return nil
}

// CreateDNSServer create a dns server on given netstack
func CreateDNSServer(s *stack.Stack, resolver *dns.Resolver, mapper *dns.ResolverEnhancer, dnsHijack []net.Addr, nicID tcpip.NICID) (*DNSServer, error) {
	var err error
	handler := dns.NewHandler(resolver, mapper)
	serverIn := &dns.Server{}
	serverIn.SetHandler(handler)
	tcpDnsArr := make([]net.TCPAddr, 0, len(dnsHijack))
	udpDnsArr := make([]net.UDPAddr, 0, len(dnsHijack))
	for _, d := range dnsHijack {
		switch d.(type) {
		case *net.TCPAddr:
			{
				tcpDnsArr = append(tcpDnsArr, *d.(*net.TCPAddr))
				break
			}
		case *net.UDPAddr:
			{
				udpDnsArr = append(udpDnsArr, *d.(*net.UDPAddr))
				break
			}
		}
	}

	endpoints, ids := hijackUdpDns(udpDnsArr, s, serverIn)
	tcpListeners, dnsServers := hijackTcpDns(tcpDnsArr, s, serverIn)
	server := &DNSServer{
		resolver:       resolver,
		stack:          s,
		udpEndpoints:   endpoints,
		udpEndpointIDs: ids,
		NICID:          nicID,
		tcpListeners:   tcpListeners,
	}

	server.dnsServers = dnsServers

	return server, err
}

func hijackUdpDns(dnsArr []net.UDPAddr, s *stack.Stack, serverIn *dns.Server) ([]*dnsEndpoint, []*stack.TransportEndpointID) {
	endpoints := make([]*dnsEndpoint, len(dnsArr))
	ids := make([]*stack.TransportEndpointID, len(dnsArr))
	for i, dns := range dnsArr {
		port := dns.Port
		ip := dns.IP
		address := tcpip.FullAddress{NIC: nicID, Port: uint16(port)}
		var protocol tcpip.NetworkProtocolNumber
		if ip.To4() != nil {
			address.Addr = tcpip.Address(ip.To4())
			protocol = ipv4.ProtocolNumber

		} else {
			address.Addr = tcpip.Address(ip.To16())
			protocol = ipv6.ProtocolNumber
		}

		protocolAddr := tcpip.ProtocolAddress{
			Protocol:          protocol,
			AddressWithPrefix: address.Addr.WithPrefix(),
		}

		// netstack will only reassemble IP fragments when its' dest ip address is registered in NIC.endpoints
		if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
			log.Errorln("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
		}

		if address.Addr == ipv4Zero || address.Addr == ipv6Zero {
			address.Addr = ""
		}

		// UDP DNS
		id := &stack.TransportEndpointID{
			LocalAddress:  address.Addr,
			LocalPort:     uint16(port),
			RemotePort:    0,
			RemoteAddress: "",
		}

		// TransportEndpoint for DNS
		endpoint := &dnsEndpoint{
			stack:    s,
			uniqueID: s.UniqueID(),
			server:   serverIn,
		}

		if tcpiperr := s.RegisterTransportEndpoint(
			[]tcpip.NetworkProtocolNumber{
				ipv4.ProtocolNumber,
				ipv6.ProtocolNumber,
			},
			udp.ProtocolNumber,
			*id,
			endpoint,
			ports.Flags{LoadBalanced: true}, // it's actually the SO_REUSEPORT. Not sure it take effect.
			nicID); tcpiperr != nil {
			log.Errorln("Unable to start UDP DNS on tun:  %v", tcpiperr.String())
		}

		ids[i] = id
		endpoints[i] = endpoint
	}

	return endpoints, ids
}

func hijackTcpDns(dnsArr []net.TCPAddr, s *stack.Stack, serverIn *dns.Server) ([]net.Listener, []*dns.Server) {
	tcpListeners := make([]net.Listener, len(dnsArr))
	dnsServers := make([]*dns.Server, len(dnsArr))

	for i, dnsAddr := range dnsArr {
		var tcpListener net.Listener
		var v4 bool
		var err error
		port := dnsAddr.Port
		ip := dnsAddr.IP
		address := tcpip.FullAddress{NIC: nicID, Port: uint16(port)}
		if ip.To4() != nil {
			address.Addr = tcpip.Address(ip.To4())
			v4 = true
		} else {
			address.Addr = tcpip.Address(ip.To16())
			v4 = false
		}

		if v4 {
			tcpListener, err = gonet.ListenTCP(s, address, ipv4.ProtocolNumber)
		} else {
			tcpListener, err = gonet.ListenTCP(s, address, ipv6.ProtocolNumber)
		}

		if err != nil {
			log.Errorln("can not listen on tun: %v, hijack tcp[%s] failed", err, dnsAddr)
		} else {
			tcpListeners[i] = tcpListener
			server := &D.Server{Listener: &ListenerWrap{
				listener: tcpListener,
			}, Handler: serverIn}
			dnsServer := dns.Server{}
			dnsServer.Server = server
			go dnsServer.ActivateAndServe()
			dnsServers[i] = &dnsServer
		}

	}
	//
	//for _, listener := range tcpListeners {
	//	server := &D.Server{Listener: listener, Handler: serverIn}
	//
	//	dnsServers = append(dnsServers, &dnsServer)
	//	go dnsServer.ActivateAndServe()
	//}

	return tcpListeners, dnsServers
}

// Stop stop the DNS Server on tun
func (s *DNSServer) Stop() {
	if s == nil {
		return
	}

	for i := 0; i < len(s.udpEndpointIDs); i++ {
		ep := s.udpEndpoints[i]
		id := s.udpEndpointIDs[i]
		// remove udp endpoint from stack
		s.stack.UnregisterTransportEndpoint(
			[]tcpip.NetworkProtocolNumber{
				ipv4.ProtocolNumber,
				ipv6.ProtocolNumber,
			},
			udp.ProtocolNumber,
			*id,
			ep,
			ports.Flags{LoadBalanced: true}, // should match the RegisterTransportEndpoint
			s.NICID)
	}

	for _, server := range s.dnsServers {
		server.Shutdown()
	}

	for _, listener := range s.tcpListeners {
		listener.Close()
	}
}

// DnsHijack return the listening address of DNS Server
func (t *gvisorAdapter) DnsHijack() []string {
	dnsHijackArr := make([]string, len(t.dnsServer.udpEndpoints))
	for _, id := range t.dnsServer.udpEndpointIDs {
		dnsHijackArr = append(dnsHijackArr, fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort))
	}

	return dnsHijackArr
}

func (t *gvisorAdapter) StopDNSServer() {
	t.dnsServer.Stop()
	log.Debugln("tun DNS server stoped")
	t.dnsServer = nil
}

// ReCreateDNSServer recreate the DNS Server on tun
func (t *gvisorAdapter) ReCreateDNSServer(resolver *dns.Resolver, mapper *dns.ResolverEnhancer, dnsHijackArr []string) error {
	t.StopDNSServer()

	if resolver == nil {
		return fmt.Errorf("failed to create DNS server on tun: resolver not provided")
	}

	if len(dnsHijackArr) == 0 {
		return fmt.Errorf("failed to create DNS server on tun: len(addrs) == 0")
	}
	var err error
	var addrs []net.Addr
	for _, addr := range dnsHijackArr {
		var (
			addrType string
			hostPort string
		)

		addrType, hostPort, err = Common.SplitNetworkType(addr)
		if err != nil {
			return err
		}

		var (
			host, port string
			hasPort    bool
		)

		host, port, hasPort, err = Common.SplitHostPort(hostPort)
		if !hasPort {
			port = "53"
		}

		switch addrType {
		case "udp", "":
			{
				var udpDNS *net.UDPAddr
				udpDNS, err = net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
				if err != nil {
					return err
				}

				addrs = append(addrs, udpDNS)
				break
			}
		case "tcp":
			{
				var tcpDNS *net.TCPAddr
				tcpDNS, err = net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
				if err != nil {
					return err
				}

				addrs = append(addrs, tcpDNS)
				break
			}
		default:
			err = fmt.Errorf("unspported dns scheme:%s", addrType)
		}

	}

	server, err := CreateDNSServer(t.ipstack, resolver, mapper, addrs, nicID)
	if err != nil {
		return err
	}

	t.dnsServer = server

	return nil
}
