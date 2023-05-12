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
var NewDeadlineEnhancePacketConn = deadline.NewEnhancePacketConn

type threadSafePacketConn struct {
	EnhancePacketConn
	access sync.Mutex
}

func (c *threadSafePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	return c.EnhancePacketConn.WriteTo(b, addr)
}

func (c *threadSafePacketConn) Upstream() any {
	return c.EnhancePacketConn
}

func (c *threadSafePacketConn) ReaderReplaceable() bool {
	return true
}

func NewThreadSafePacketConn(pc net.PacketConn) net.PacketConn {
	return &threadSafePacketConn{EnhancePacketConn: NewEnhancePacketConn(pc)}
}
