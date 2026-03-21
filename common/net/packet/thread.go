package packet

import (
	"net"
	"sync"
)

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

func NewThreadSafePacketConn(pc net.PacketConn) EnhancePacketConn {
	tsPC := &threadSafePacketConn{EnhancePacketConn: NewEnhancePacketConn(pc)}
	if singPC, isSingPC := pc.(SingPacketConn); isSingPC {
		return &threadSafeSingPacketConn{
			threadSafePacketConn: tsPC,
			singPacketConn:       singPC,
		}
	}
	return tsPC
}
