package tunnel

import (
	C "github.com/metacubex/mihomo/constant"
)

// Remote resolution is deliberately internal until every protocol has migrated.
// Each session snapshots it before sniffing or selecting an outbound.
var udpRemoteResolve bool

type udpSession struct {
	C.PacketSender
	sender      *packetSender
	destination *udpDestination
}

func newUDPSession(destination *udpDestination) *udpSession {
	sender := newPacketSender().(*packetSender)
	sender.first = destination
	sender.allowRemote = destination.Route.UDP.AllowRemote
	return &udpSession{PacketSender: sender, sender: sender, destination: destination}
}

func (s *udpSession) bind(pc C.PacketConn) {
	destination := s.destination
	destination.Target = destination.Route.UDP.Target
	prepared := pc.InitialDestination()
	s.sender.mapping.register(destination.Origin, destination.Target, prepared,
		destination.direct, pc.UDPCapabilities())
	if prepared.IsValid() {
		s.sender.destinations[destination.key] = udpNetAddr(prepared)
	}
}
