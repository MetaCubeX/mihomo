package tunnel

import (
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

// One atomic snapshot prevents a reload from mixing permission and mapping.
// The zero value deliberately keeps local resolution and endpoint independence.
var udpSettings atomic.Uint32

func UDPConfig() (bool, C.UDPMapping) {
	value := udpSettings.Load()
	return value&1 != 0, C.UDPMapping(value >> 1)
}

func SetUDPConfig(remote bool, mapping C.UDPMapping) {
	value := uint32(mapping) << 1
	if remote {
		value |= 1
	}
	udpSettings.Store(value)
}

func PatchUDPConfig(remote *bool, mapping *C.UDPMapping) {
	for {
		old := udpSettings.Load()
		value := old
		if remote != nil {
			value &^= 1
			if *remote {
				value |= 1
			}
		}
		if mapping != nil {
			value = uint32(*mapping)<<1 | value&1
		}
		if udpSettings.CompareAndSwap(old, value) {
			return
		}
	}
}

type udpSession struct {
	C.PacketSender
	sender      *packetSender
	destination *udpDestination
	key         C.UDPSessionKey
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
