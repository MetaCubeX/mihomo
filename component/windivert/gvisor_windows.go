//go:build windows && with_gvisor && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"fmt"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	tun "github.com/metacubex/sing-tun"
)

func (t *Tun) startGVisor() error {
	endpoint := channel.New(batchSize, t.options.MTU, "")
	// Outbound packets may still contain hardware-offloaded checksums.
	endpoint.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
	ipStack, err := tun.NewGVisorStack(endpoint)
	if err != nil {
		endpoint.Close()
		return err
	}
	t.closeStack = func() {
		endpoint.Attach(nil)
		endpoint.Close()
		ipStack.Close()
		for _, endpoint := range ipStack.CleanupEndpoints() {
			endpoint.Abort()
		}
	}
	// SACK recovery handles the short RTT of the local Windows TCP leg.
	recovery := tcpip.TCPRecovery(0)
	if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
		return fmt.Errorf("WFP TCP recovery: %s", err)
	}
	if t.options.Stack == "gvisor" {
		ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tun.NewTCPForwarder(t.ctx, ipStack, t.options.Handler).HandlePacket)
	}
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, tun.NewUDPForwarder(t.ctx, ipStack, t.options.Handler).HandlePacket)
	t.deliver = func(p []byte, info packetInfo, _ address) {
		protocol := header.IPv4ProtocolNumber
		if info.source.Addr().Is6() {
			protocol = header.IPv6ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p[:info.size]), IsForwardedPacket: true})
		endpoint.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
	t.running.Add(1)
	go func() {
		defer t.running.Done()
		batch := newPacketWriter(t)
		defer batch.release()
		for {
			pkt := endpoint.ReadContext(t.ctx)
			if pkt == nil {
				return
			}
			for count := 0; pkt != nil; count++ {
				addr, ok := t.responseInterface(packetDestination(pkt.NetworkHeader().Slice()))
				if ok {
					addr.Flags = flagIPChecksum | flagTCPChecksum | flagUDPChecksum
					var key uint32
					if transport := pkt.TransportHeader().Slice(); len(transport) >= 4 {
						key = binary.BigEndian.Uint32(transport)
					}
					batch.append(addr, key, pkt.AsSlices()...)
				}
				pkt.DecRef()
				if count+1 == batchSize {
					break
				}
				pkt = endpoint.Read()
			}
			batch.flush()
		}
	}()
	return nil
}
