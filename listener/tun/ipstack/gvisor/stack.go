//go:build !no_gvisor

// Package gvisor provides a thin wrapper around a gVisor's stack.
package gvisor

import (
	"net/netip"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/option"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type gvStack struct {
	*stack.Stack
	device device.Device
}

func (s *gvStack) Close() error {
	var err error
	if s.device != nil {
		err = s.device.Close()
	}
	if s.Stack != nil {
		s.Stack.Close()
		s.Stack.Wait()
	}
	return err
}

// New allocates a new *gvStack with given options.
func New(device device.Device, dnsHijack []netip.AddrPort, tunAddress netip.Prefix, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter, opts ...option.Option) (ipstack.Stack, error) {
	s := &gvStack{
		Stack: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol4,
				icmp.NewProtocol6,
			},
		}),

		device: device,
	}

	handler := &gvHandler{
		gateway:   tunAddress.Masked().Addr().Next(),
		dnsHijack: dnsHijack,
		tcpIn:     tcpIn,
		udpIn:     udpIn,
	}

	// Generate unique NIC id.
	nicID := tcpip.NICID(s.Stack.UniqueID())
	defaultOpts := []option.Option{option.WithDefault()}
	defaultOpts = append(defaultOpts, opts...)
	opts = append(defaultOpts,
		// Create stack NIC and then bind link endpoint to it.
		withCreatingNIC(nicID, device),

		// In the past we did s.AddAddressRange to assign 0.0.0.0/0
		// onto the interface. We need that to be able to terminate
		// all the incoming connections - to any ip. AddressRange API
		// has been removed and the suggested workaround is to use
		// Promiscuous mode. https://github.com/google/gvisor/issues/3876
		//
		// Ref: https://github.com/cloudflare/slirpnetstack/blob/master/stack.go
		withPromiscuousMode(nicID, nicPromiscuousModeEnabled),

		// Enable spoofing if a stack may send packets from unowned
		// addresses. This change required changes to some netgophers
		// since previously, promiscuous mode was enough to let the
		// netstack respond to all incoming packets regardless of the
		// packet's destination address. Now that a stack.Route is not
		// held for each incoming packet, finding a route may fail with
		// local addresses we don't own but accepted packets for while
		// in promiscuous mode. Since we also want to be able to send
		// from any address (in response the received promiscuous mode
		// packets), we need to enable spoofing.
		//
		// Ref: https://github.com/google/gvisor/commit/8c0701462a84ff77e602f1626aec49479c308127
		withSpoofing(nicID, nicSpoofingEnabled),

		// Add default route table for IPv4 and IPv6. This will handle
		// all incoming ICMP packets.
		withRouteTable(nicID),

		// Initiate transport protocol (TCP/UDP) with given handler.
		withTCPHandler(handler.HandleTCP), withUDPHandler(handler.HandleUDP),
	)

	for _, opt := range opts {
		if err := opt(s.Stack); err != nil {
			return nil, err
		}
	}
	return s, nil
}
