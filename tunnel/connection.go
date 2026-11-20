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

	mu          sync.Mutex
	closed      bool
	mapping     *udpNAT
	first       *udpDestination
	allowRemote bool

	// Seeded before Process starts, then owned by its single consumer. Cache
	// the wire address too, so hits need neither NAT locking nor allocations.
	destinations map[udpPacketKey]net.Addr
}

type udpPacketKey struct {
	address netip.AddrPort
	host    string
}

func udpPacketKeyFromMetadata(metadata *C.Metadata) udpPacketKey {
	// Use the inbound identity; hosts, rules and sniffing only change Route.
	key := udpPacketKey{address: netip.AddrPortFrom(metadata.DstIP, metadata.DstPort)}
	if !metadata.DstIP.IsValid() {
		key.host = metadata.Host
	}
	return key
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

		mapping:      newUDPNAT(),
		destinations: make(map[udpPacketKey]net.Addr),
	}
}

func (s *packetSender) processPacket(pc C.PacketConn, packet C.PacketAdapter) {
	defer packet.Drop()
	metadata := packet.Metadata()
	key := udpPacketKeyFromMetadata(metadata)
	if address, loaded := s.destinations[key]; loaded {
		_ = handleUDPToRemote(packet, pc, address)
		return
	}

	identity := ""
	if s.first != nil {
		identity = s.first.Route.UDP.SessionKey
	}
	destination := newUDPDestination(metadata, s.allowRemote, identity)
	if s.first != nil && destination.Origin == s.first.Origin {
		// Sniffing belongs to the initial target, not every packet sharing a source.
		destination.Route = s.first.Route.Clone()
		destination.Route.DstPort = destination.Origin.Port
		destination.Route.UDP.Target.Port = destination.Origin.Port
		destination.Target = destination.Route.UDP.Target
		destination.fixedIP = s.first.fixedIP
	} else if err := destination.prepare(); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}
	prepared, cached := s.mapping.cached(destination.Origin, destination.Target)
	if !cached {
		// Keep preparation in the single consumer: resolving in another goroutine
		// would reorder datagrams and their NAT records.
		var err error
		prepared, err = pc.PrepareUDP(s.ctx, destination.dialMetadata())
		if err != nil {
			log.Warnln("[UDP] Prepare destination error: %s", err)
			return
		}
	}
	if !prepared.IsValid() {
		log.Warnln("[UDP] Destination address not valid: %s", prepared)
		return
	}
	// Publish before WriteTo: even an immediate response must see this target.
	s.mapping.register(destination.Origin, destination.Target, prepared, destination.direct, pc.UDPCapabilities())
	address := udpNetAddr(prepared)
	s.destinations[key] = address
	_ = handleUDPToRemote(packet, pc, address)
}

func (s *packetSender) Process(pc C.PacketConn, proxy C.WriteBackProxy) {
	for {
		select {
		case <-s.ctx.Done():
			return // sender closed
		case packet := <-s.ch:
			if s.ctx.Err() != nil {
				packet.Drop()
				return
			}
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		packet.Drop() // sender closed before Send()
		return
	}

	select {
	case s.ch <- packet:
		// put ok, so don't drop packet, will process by other side of chan
	default:
		packet.Drop() // chan is full
	}
}

func (s *packetSender) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
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

func handleUDPToLocal(writeBack C.WriteBack, pc C.PacketConn, sender C.PacketSender, mapping *udpNAT, key C.UDPSessionKey) {
	defer func() {
		sender.Close()
		_ = pc.Close()
		natTable.DeleteSession(key, sender)
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		data, put, from, err := pc.WaitReadFrom()
		if err != nil {
			if put != nil {
				put()
			}
			return
		}
		address, err := udpSocksaddr(from)
		if err == nil {
			address, err = mapping.restore(address)
		}
		if err != nil {
			if put != nil {
				put()
			}
			log.Debugln("[UDP] Drop reply with invalid source address: %s", err)
			continue
		}
		_, err = writeBack.WriteBack(data, udpNetAddr(address))
		if put != nil {
			put()
		}
		if err != nil {
			return
		}
	}
}

func udpNetAddr(address M.Socksaddr) net.Addr {
	if address.IsIP() {
		return address.UDPAddr()
	}
	return address
}

func udpSocksaddr(address net.Addr) (M.Socksaddr, error) {
	var result M.Socksaddr
	switch address := address.(type) {
	case *net.UDPAddr:
		if address == nil || address.Port < 0 || address.Port > 65535 {
			return result, errors.New("invalid UDP source address")
		}
		result = M.SocksaddrFromNet(address)
	case M.Socksaddr:
		result = address
	case *M.Socksaddr:
		if address == nil {
			return result, errors.New("missing UDP source address")
		}
		result = *address
	default:
		return result, errors.New("unsupported UDP source address")
	}
	if !result.IsValid() || result.IsIP() && result.Fqdn != "" {
		return M.Socksaddr{}, errors.New("invalid UDP source address")
	}
	return result.Unwrap(), nil
}

func handleSocket(inbound, outbound net.Conn) {
	N.Relay(inbound, outbound)
}
