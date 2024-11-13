package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type packetSender struct {
	ctx    context.Context
	cancel context.CancelFunc
	ch     chan C.PacketAdapter
	cache  *lru.LruCache[string, netip.Addr]
}

// newPacketSender return a chan based C.PacketSender
// It ensures that packets can be sent sequentially and without blocking
func newPacketSender() C.PacketSender {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan C.PacketAdapter, senderCapacity)
	return &packetSender{
		ctx:    ctx,
		cancel: cancel,
		ch:     ch,
		cache:  lru.New[string, netip.Addr](lru.WithSize[string, netip.Addr](senderCapacity)),
	}
}

func (s *packetSender) Process(pc C.PacketConn, proxy C.WriteBackProxy) {
	for {
		select {
		case <-s.ctx.Done():
			return // sender closed
		case packet := <-s.ch:
			if proxy != nil {
				proxy.UpdateWriteBack(packet)
			}
			if err := s.ResolveUDP(packet.Metadata()); err != nil {
				log.Warnln("[UDP] Resolve Ip error: %s", err)
			} else {
				_ = handleUDPToRemote(packet, pc, packet.Metadata())
			}
			packet.Drop()
		}
	}
}

func (s *packetSender) dropAll() {
	for {
		select {
		case data := <-s.ch:
			data.Drop() // drop all data still in chan
		default:
			return // no data, exit goroutine
		}
	}
}

func (s *packetSender) Send(packet C.PacketAdapter) {
	select {
	case <-s.ctx.Done():
		packet.Drop() // sender closed before Send()
		return
	default:
	}

	select {
	case s.ch <- packet:
		// put ok, so don't drop packet, will process by other side of chan
	case <-s.ctx.Done():
		packet.Drop() // sender closed when putting data to chan
	default:
		packet.Drop() // chan is full
	}
}

func (s *packetSender) Close() {
	s.cancel()
	s.dropAll()
}

func (s *packetSender) ResolveUDP(metadata *C.Metadata) (err error) {
	// local resolve UDP dns
	if !metadata.Resolved() {
		ip, ok := s.cache.Get(metadata.Host)
		if !ok {
			ip, err = resolver.ResolveIP(s.ctx, metadata.Host)
			if err != nil {
				return err
			}
			s.cache.Set(metadata.Host, ip)
		}

		metadata.DstIP = ip
	}
	return nil
}

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, metadata *C.Metadata) error {
	addr := metadata.UDPAddr()
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(writeBack C.WriteBack, pc N.EnhancePacketConn, sender C.PacketSender, key string, oAddrPort netip.AddrPort, fAddr netip.Addr) {
	defer func() {
		sender.Close()
		_ = pc.Close()
		closeAllLocalCoon(key)
		natTable.Delete(key)
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		data, put, from, err := pc.WaitReadFrom()
		if err != nil {
			return
		}

		fromUDPAddr, isUDPAddr := from.(*net.UDPAddr)
		if !isUDPAddr {
			fromUDPAddr = net.UDPAddrFromAddrPort(oAddrPort) // oAddrPort was Unmapped
			log.Warnln("server return a [%T](%s) which isn't a *net.UDPAddr, force replace to (%s), this may be caused by a wrongly implemented server", from, from, oAddrPort)
		} else if fromUDPAddr == nil {
			fromUDPAddr = net.UDPAddrFromAddrPort(oAddrPort) // oAddrPort was Unmapped
			log.Warnln("server return a nil *net.UDPAddr, force replace to (%s), this may be caused by a wrongly implemented server", oAddrPort)
		} else {
			_fromUDPAddr := *fromUDPAddr
			fromUDPAddr = &_fromUDPAddr // make a copy
			if fromAddr, ok := netip.AddrFromSlice(fromUDPAddr.IP); ok {
				fromAddr = fromAddr.Unmap()
				if fAddr.IsValid() && (oAddrPort.Addr() == fromAddr) { // oAddrPort was Unmapped
					fromAddr = fAddr.Unmap()
				}
				fromUDPAddr.IP = fromAddr.AsSlice()
				if fromAddr.Is4() {
					fromUDPAddr.Zone = "" // only ipv6 can have the zone
				}
			}
		}

		_, err = writeBack.WriteBack(data, fromUDPAddr)
		if put != nil {
			put()
		}
		if err != nil {
			return
		}
	}
}

func closeAllLocalCoon(lAddr string) {
	natTable.RangeForLocalConn(lAddr, func(key string, value *net.UDPConn) bool {
		conn := value

		conn.Close()
		log.Debugln("Closing TProxy local conn... lAddr=%s rAddr=%s", lAddr, key)
		return true
	})
}

func handleSocket(inbound, outbound net.Conn) {
	N.Relay(inbound, outbound)
}
