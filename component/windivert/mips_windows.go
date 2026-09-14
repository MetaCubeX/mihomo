//go:build windows && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mipstack"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (t *Tun) startMIPS() error {
	ipStack, err := mipstack.New(mipstack.Config{
		Promiscuous: true,
		MTU:         t.options.MTU,
		TCP: mipstack.TCPSocketDefaults{
			KeepAlive: true,
			KeepAliveConfig: mipstack.KeepAliveConfig{
				Idle: 15 * time.Second, Interval: 15 * time.Second,
			},
		},
	})
	if err != nil {
		return err
	}
	t.closeStack = func() { _ = ipStack.Close() }
	if _, err = mipstack.NewTCPForwarder(ipStack, mipstack.TCPForwarderOptions{}, t.forwardMIPSTCP); err != nil {
		return err
	}
	if _, err = mipstack.NewUDPForwarder(ipStack, mipstack.UDPForwarderOptions{}, t.forwardMIPSUDP); err != nil {
		return err
	}
	if err = ipStack.Start(); err != nil {
		return err
	}
	// Only local source addresses need an interface entry, as in the gVisor path.
	var interfaceMu sync.RWMutex
	interfaces := make(map[netip.Addr]address)
	t.deliver = func(p []byte, info packetInfo, addr address) {
		interfaceMu.Lock()
		interfaces[info.source.Addr()] = addr
		interfaceMu.Unlock()
		// Write consumes the packet synchronously, so the receive buffer can be reused.
		_, _ = ipStack.Write([][]byte{p[:info.size]}, 0)
	}
	t.running.Add(1)
	go func() {
		defer t.running.Done()
		buffers := make([][]byte, ipStack.BatchSize())
		for i := range buffers {
			buffers[i] = make([]byte, t.options.MTU)
		}
		sizes := make([]int, len(buffers))
		for {
			n, err := ipStack.Read(buffers, sizes, 0)
			for i := 0; i < n; i++ {
				p := buffers[i][:sizes[i]]
				// Stack output is valid IP, including fragments of large UDP replies.
				destination, _ := netip.AddrFromSlice(p[16:20])
				if p[0]>>4 == 6 {
					destination, _ = netip.AddrFromSlice(p[24:40])
				}
				interfaceMu.RLock()
				addr, ok := interfaces[destination]
				interfaceMu.RUnlock()
				if !ok {
					if t.ctx.Err() == nil {
						log.Warnln("[WFP] response interface not found for %s", destination)
					}
					continue
				}
				// MIPS already calculated these checksums; inject as inbound.
				addr.Flags = flagIPChecksum | flagTCPChecksum | flagUDPChecksum
				if _, err := t.handle.send(p, &addr); err != nil && t.ctx.Err() == nil {
					log.Warnln("[WFP] send: packet dropped: %s", err)
				}
			}
			if err != nil {
				if t.ctx.Err() == nil {
					t.close(fmt.Errorf("read MIPS packet: %w", err))
				}
				return
			}
		}
	}()
	return nil
}

func (t *Tun) forwardMIPSTCP(request *mipstack.TCPForwarderRequest) {
	flow := request.Flow()
	conn, err := request.Accept(t.ctx)
	if err != nil {
		return
	}
	go func() {
		defer conn.Close()
		if err := t.options.Handler.NewConnection(t.ctx, conn, M.Metadata{
			Source: M.SocksaddrFromNetIP(flow.Source), Destination: M.SocksaddrFromNetIP(flow.Destination),
		}); err != nil {
			_ = conn.SetLinger(0)
		}
	}()
}

func (t *Tun) forwardMIPSUDP(request *mipstack.UDPForwarderRequest) {
	flow := request.Flow()
	responder, err := request.DetachForReplies()
	if err != nil {
		return
	}
	t.options.Handler.NewPacket(t.ctx, flow.Source, buf.As(request.Payload()).ToOwned(), M.Metadata{
		Source: M.SocksaddrFromNetIP(flow.Source), Destination: M.SocksaddrFromNetIP(flow.Destination),
	}, func(N.PacketConn) N.PacketWriter { return &mipsUDPWriter{responder: responder} })
}

type mipsUDPWriter struct {
	responder *mipstack.UDPForwarderResponder
}

func (w *mipsUDPWriter) WritePacket(buffer *buf.Buffer, source M.Socksaddr) error {
	defer buffer.Release()
	_, err := w.responder.ReplyFrom(buffer.Bytes(), source.AddrPort())
	return err
}

// Complete outbound checksums before MIPS validates the packet.
// info comes from parsePacket, which excludes fragments and truncated headers.
func completeChecksums(p []byte, info packetInfo, flags uint32) bool {
	// Windows can leave the IPv4 checksum zero even with IPChecksum set.
	if info.source.Addr().Is4() && (flags&flagIPChecksum == 0 || binary.BigEndian.Uint16(p[10:]) == 0) {
		p[10], p[11] = 0, 0
		binary.BigEndian.PutUint16(p[10:], mipstack.InternetChecksum(p[:info.offset]))
	}
	payload := p[info.offset:info.size]
	checksumOffset, checksumFlag := 16, uint32(flagTCPChecksum)
	if info.protocol == 17 {
		length := int(binary.BigEndian.Uint16(payload[4:]))
		if length < 8 || length > len(payload) {
			return false
		}
		payload = payload[:length]
		checksumOffset, checksumFlag = 6, flagUDPChecksum
	}
	if flags&checksumFlag == 0 {
		payload[checksumOffset], payload[checksumOffset+1] = 0, 0
		checksum, err := mipstack.IPTransportChecksum(info.source.Addr(), info.destination.Addr(), int(info.protocol), payload)
		if err != nil {
			return false
		}
		if info.protocol == 17 && checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(payload[checksumOffset:], checksum)
	}
	return true
}
