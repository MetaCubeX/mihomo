//go:build windows && with_gvisor && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
)

func (t *Tun) startGVisor() error {
	endpoint := channel.New(256, t.options.MTU, "")
	// Captured packets may still contain hardware-offloaded checksums.
	endpoint.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
	ipStack, err := tun.NewGVisorStack(endpoint)
	if err != nil {
		endpoint.Close()
		return err
	}
	// SACK recovery handles the short RTT of the local Windows TCP leg.
	recovery := tcpip.TCPRecovery(0)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery)
	if t.options.Stack == "gvisor" {
		ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tun.NewTCPForwarder(t.ctx, ipStack, t.options.Handler).HandlePacket)
	}
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, tun.NewUDPForwarder(t.ctx, ipStack, t.options.Handler).HandlePacket)
	t.deliver = func(p []byte, info packetInfo, _ address) {
		protocol := header.IPv4ProtocolNumber
		if info.source.Addr().Is6() {
			protocol = header.IPv6ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(p), IsForwardedPacket: true,
		})
		endpoint.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
	t.closeStack = func() {
		endpoint.Close()
		endpoint.Attach(nil)
		ipStack.Close()
		for _, endpoint := range ipStack.CleanupEndpoints() {
			endpoint.Abort()
		}
	}
	t.running.Add(1)
	go func() {
		defer t.running.Done()
		batch := newPacketWriter(t)
		for {
			pkt := endpoint.ReadContext(t.ctx)
			if pkt == nil {
				return
			}
			for pkt != nil {
				destination := packetDestination(pkt.NetworkHeader().Slice())
				addr, ok := t.responseInterface(destination)
				if ok {
					addr.Flags = flagIPChecksum | flagTCPChecksum | flagUDPChecksum
					var key uint32
					if transport := pkt.TransportHeader().Slice(); len(transport) >= 4 {
						key = binary.BigEndian.Uint32(transport)
					}
					batch.append(addr, key, pkt.AsSlices()...)
				} else if t.ctx.Err() == nil {
					log.Warnln("[WFP] response interface not found for %s", destination)
				}
				pkt.DecRef()
				pkt = endpoint.Read()
			}
			batch.flush()
		}
	}()
	return nil
}
