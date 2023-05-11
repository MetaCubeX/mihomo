package net

import (
	"net"
	"sync"

	"github.com/Dreamacro/clash/common/net/deadline"
	"github.com/Dreamacro/clash/common/net/packet"
)

type EnhancePacketConn = packet.EnhancePacketConn

var NewEnhancePacketConn = packet.NewEnhancePacketConn
var NewDeadlinePacketConn = deadline.NewPacketConn

type threadSafePacketConn struct {
	net.PacketConn
	access sync.Mutex
}

func (c *threadSafePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	return c.PacketConn.WriteTo(b, addr)
}

func (c *threadSafePacketConn) Upstream() any {
	return c.PacketConn
}

func NewThreadSafePacketConn(pc net.PacketConn) net.PacketConn {
	return &threadSafePacketConn{PacketConn: pc}
}
