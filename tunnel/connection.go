package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	M "github.com/metacubex/sing/common/metadata"
)

type packetSender struct {
	ctx    context.Context
	cancel context.CancelFunc
	ch     chan C.PacketAdapter

	// destination NAT mapping
	originToTarget map[string]netip.Addr
	targetToOrigin map[netip.Addr]netip.Addr
	// domainToOrigin maps an XUDP domain to the client-facing destination, usually a fake-ip.
	domainToOrigin map[string]netip.Addr
	// unboundDomain is the set of domains not yet tied to a reply IP.
	unboundDomain map[string]struct{}
	mappingMutex  sync.RWMutex
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

		originToTarget: make(map[string]netip.Addr),
		targetToOrigin: make(map[netip.Addr]netip.Addr),
		domainToOrigin: make(map[string]netip.Addr),
		unboundDomain:  make(map[string]struct{}),
	}
}

func (s *packetSender) AddMapping(originMetadata *C.Metadata, metadata *C.Metadata) {
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()
	originKey := originMetadata.String()
	originAddr := originMetadata.DstIP
	targetAddr := metadata.DstIP
	if addr := s.originToTarget[originKey]; !addr.IsValid() { // overwrite only if the record is illegal
		s.originToTarget[originKey] = targetAddr
	}
	if addr := s.targetToOrigin[targetAddr]; !addr.IsValid() { // overwrite only if the record is illegal
		s.targetToOrigin[targetAddr] = originAddr
	}
}

func (s *packetSender) RestoreReadFrom(addr netip.Addr) netip.Addr {
	s.mappingMutex.RLock()
	defer s.mappingMutex.RUnlock()
	if originAddr := s.targetToOrigin[addr]; originAddr.IsValid() {
		return originAddr
	}
	return addr
}

func (s *packetSender) rememberDomain(origin netip.Addr, host string) {
	if host == "" || !origin.IsValid() {
		return
	}
	origin = origin.Unmap()
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()
	if _, ok := s.domainToOrigin[host]; ok {
		return
	}
	s.domainToOrigin[host] = origin
	s.unboundDomain[host] = struct{}{}
}

// restoreReply rewrites a server reply address back to the client-facing destination.
// A public IP is bound only when exactly one domain is still unbound.
func (s *packetSender) restoreReply(from net.Addr, fallback netip.AddrPort) netip.AddrPort {
	if socks, ok := from.(M.Socksaddr); ok && socks.IsFqdn() {
		s.mappingMutex.RLock()
		origin := s.domainToOrigin[socks.Fqdn]
		s.mappingMutex.RUnlock()
		if origin.IsValid() {
			port := socks.Port
			if port == 0 {
				port = fallback.Port()
			}
			return netip.AddrPortFrom(origin, port)
		}
	}

	ip, port, ok := replyIP(from)
	if !ok {
		return fallback
	}
	if origin, learned := s.learnReplyIP(ip); learned {
		return netip.AddrPortFrom(origin, port)
	}
	return netip.AddrPortFrom(s.RestoreReadFrom(ip).Unmap(), port)
}

func (s *packetSender) learnReplyIP(reply netip.Addr) (netip.Addr, bool) {
	reply = reply.Unmap()
	if !reply.IsValid() {
		return netip.Addr{}, false
	}
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()
	if origin := s.targetToOrigin[reply]; origin.IsValid() {
		return origin, true
	}
	if len(s.unboundDomain) != 1 {
		return netip.Addr{}, false
	}
	var host string
	for candidate := range s.unboundDomain {
		host = candidate
	}
	origin := s.domainToOrigin[host]
	if !origin.IsValid() {
		return netip.Addr{}, false
	}
	s.targetToOrigin[reply] = origin
	delete(s.unboundDomain, host)
	return origin, true
}

func replyIP(from net.Addr) (netip.Addr, uint16, bool) {
	switch addr := from.(type) {
	case *net.UDPAddr:
		if addr == nil {
			return netip.Addr{}, 0, false
		}
		ap := addr.AddrPort()
		return ap.Addr().Unmap(), ap.Port(), ap.Addr().IsValid()
	case M.Socksaddr:
		if !addr.IsIP() {
			return netip.Addr{}, 0, false
		}
		return addr.Addr.Unmap(), addr.Port, addr.Addr.IsValid()
	default:
		return netip.Addr{}, 0, false
	}
}

func (s *packetSender) processPacket(pc C.PacketConn, packet C.PacketAdapter) {
	defer packet.Drop()
	metadata := packet.Metadata()

	var addr net.Addr

	s.mappingMutex.RLock()
	targetAddr := s.originToTarget[metadata.String()]
	s.mappingMutex.RUnlock()

	if targetAddr.IsValid() {
		addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(targetAddr, metadata.DstPort))
	}

	if addr == nil {
		originMetadata := metadata  // save origin metadata
		metadata = metadata.Clone() // don't modify PacketAdapter's metadata

		_ = preHandleMetadata(metadata) // error was pre-checked
		metadata = metadata.Pure()
		if metadata.Host != "" && pc.RelayUDPDomain() {
			s.rememberDomain(originMetadata.DstIP, metadata.Host)
			addr = M.Socksaddr{
				Fqdn: metadata.Host,
				Port: metadata.DstPort,
			}
		} else {
			if metadata.Host != "" {
				// TODO: ResolveUDP may take a long time to block the Process loop
				//       but we want keep sequence sending so can't open a new goroutine
				if err := pc.ResolveUDP(s.ctx, metadata); err != nil {
					log.Warnln("[UDP] Resolve Ip error: %s", err)
					return
				}
			}

			if !metadata.DstIP.IsValid() {
				log.Warnln("[UDP] Destination ip not valid: %#v", metadata)
				return
			}
			s.AddMapping(originMetadata, metadata)
			addr = metadata.UDPAddr()
		}
	}
	_ = handleUDPToRemote(packet, pc, addr)
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
			s.processPacket(pc, packet)
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

func (s *packetSender) DoSniff(metadata *C.Metadata) error { return nil }

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, addr net.Addr) error {
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

func handleUDPToLocal(writeBack C.WriteBack, pc C.PacketConn, sender C.PacketSender, key string, oAddrPort netip.AddrPort) {
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

		var fromAddrPort netip.AddrPort
		if ps, ok := sender.(*packetSender); ok {
			fromAddrPort = ps.restoreReply(from, oAddrPort)
		} else {
			fromUDPAddr, isUDPAddr := from.(*net.UDPAddr)
			if !isUDPAddr || fromUDPAddr == nil {
				fromUDPAddr = net.UDPAddrFromAddrPort(oAddrPort)
				log.Warnln("server return a [%T](%s) which isn't a *net.UDPAddr, force replace to (%s), this may be caused by a wrongly implemented server", from, from, oAddrPort)
			}
			restored := sender.RestoreReadFrom(fromUDPAddr.AddrPort().Addr().Unmap()).Unmap()
			fromAddrPort = netip.AddrPortFrom(restored, fromUDPAddr.AddrPort().Port())
		}

		_, err = writeBack.WriteBack(data, net.UDPAddrFromAddrPort(fromAddrPort))
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
