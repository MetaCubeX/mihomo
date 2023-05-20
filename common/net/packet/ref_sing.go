package packet

import (
	"runtime"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type refSingPacketConn struct {
	*refPacketConn
	singPacketConn SingPacketConn
}

var _ N.NetPacketConn = (*refSingPacketConn)(nil)

func (c *refSingPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer runtime.KeepAlive(c.ref)
	return c.singPacketConn.WritePacket(buffer, destination)
}

func (c *refSingPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	defer runtime.KeepAlive(c.ref)
	return c.singPacketConn.ReadPacket(buffer)
}
