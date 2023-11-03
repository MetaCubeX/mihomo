package context

import (
	"net"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"

	"github.com/gofrs/uuid/v5"
)

type PacketConnContext struct {
	id         uuid.UUID
	metadata   *C.Metadata
	packetConn net.PacketConn
}

func NewPacketConnContext(metadata *C.Metadata) *PacketConnContext {
	return &PacketConnContext{
		id:       utils.NewUUIDV4(),
		metadata: metadata,
	}
}

// ID implement C.PacketConnContext ID
func (pc *PacketConnContext) ID() uuid.UUID {
	return pc.id
}

// Metadata implement C.PacketConnContext Metadata
func (pc *PacketConnContext) Metadata() *C.Metadata {
	return pc.metadata
}

// PacketConn implement C.PacketConnContext PacketConn
func (pc *PacketConnContext) PacketConn() net.PacketConn {
	return pc.packetConn
}

// InjectPacketConn injectPacketConn manually
func (pc *PacketConnContext) InjectPacketConn(pconn C.PacketConn) {
	pc.packetConn = pconn
}
