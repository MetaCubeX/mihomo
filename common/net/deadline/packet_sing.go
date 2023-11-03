package deadline

import (
	"os"
	"runtime"

	"github.com/metacubex/mihomo/common/net/packet"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type SingPacketConn struct {
	*NetPacketConn
	singPacketConn
}

var _ packet.SingPacketConn = (*SingPacketConn)(nil)

func NewSingPacketConn(pc packet.SingPacketConn) packet.SingPacketConn {
	return NewNetPacketConn(pc).(packet.SingPacketConn)
}

type EnhanceSingPacketConn struct {
	*EnhancePacketConn
	singPacketConn
}

func NewEnhanceSingPacketConn(pc packet.EnhanceSingPacketConn) packet.EnhanceSingPacketConn {
	return NewNetPacketConn(pc).(packet.EnhanceSingPacketConn)
}

var _ packet.EnhanceSingPacketConn = (*EnhanceSingPacketConn)(nil)

type singReadResult struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
	err         error
}

type singPacketConn struct {
	netPacketConn  *NetPacketConn
	singPacketConn packet.SingPacketConn
}

func (c *singPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
FOR:
	for {
		select {
		case result := <-c.netPacketConn.resultCh:
			if result != nil {
				if result, ok := result.(*singReadResult); ok {
					destination = result.destination
					err = result.err
					n, _ := buffer.Write(result.buffer.Bytes())
					result.buffer.Advance(n)
					if result.buffer.IsEmpty() {
						result.buffer.Release()
					}
					c.netPacketConn.resultCh <- nil // finish cache read
					return
				}
				c.netPacketConn.resultCh <- result // another type of read
				runtime.Gosched()                  // allowing other goroutines to run
				continue FOR
			} else {
				c.netPacketConn.resultCh <- nil
				break FOR
			}
		case <-c.netPacketConn.pipeDeadline.wait():
			return M.Socksaddr{}, os.ErrDeadlineExceeded
		}
	}

	if c.netPacketConn.disablePipe.Load() {
		return c.singPacketConn.ReadPacket(buffer)
	} else if c.netPacketConn.deadline.Load().IsZero() {
		c.netPacketConn.inRead.Store(true)
		defer c.netPacketConn.inRead.Store(false)
		destination, err = c.singPacketConn.ReadPacket(buffer)
		return
	}

	<-c.netPacketConn.resultCh
	go c.pipeReadPacket(buffer.FreeLen())

	return c.ReadPacket(buffer)
}

func (c *singPacketConn) pipeReadPacket(pLen int) {
	buffer := buf.NewSize(pLen)
	destination, err := c.singPacketConn.ReadPacket(buffer)
	result := &singReadResult{}
	result.destination = destination
	result.err = err
	c.netPacketConn.resultCh <- result
}

func (c *singPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.singPacketConn.WritePacket(buffer, destination)
}

func (c *singPacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	prw, isReadWaiter := bufio.CreatePacketReadWaiter(c.singPacketConn)
	if isReadWaiter {
		return &singPacketReadWaiter{
			netPacketConn:    c.netPacketConn,
			packetReadWaiter: prw,
		}, true
	}
	return nil, false
}

var _ N.PacketReadWaiter = (*singPacketReadWaiter)(nil)

type singPacketReadWaiter struct {
	netPacketConn    *NetPacketConn
	packetReadWaiter N.PacketReadWaiter
}

type singWaitReadResult singReadResult

func (c *singPacketReadWaiter) InitializeReadWaiter(newBuffer func() *buf.Buffer) {
	c.packetReadWaiter.InitializeReadWaiter(newBuffer)
}

func (c *singPacketReadWaiter) WaitReadPacket() (destination M.Socksaddr, err error) {
FOR:
	for {
		select {
		case result := <-c.netPacketConn.resultCh:
			if result != nil {
				if result, ok := result.(*singWaitReadResult); ok {
					destination = result.destination
					err = result.err
					c.netPacketConn.resultCh <- nil // finish cache read
					return
				}
				c.netPacketConn.resultCh <- result // another type of read
				runtime.Gosched()                  // allowing other goroutines to run
				continue FOR
			} else {
				c.netPacketConn.resultCh <- nil
				break FOR
			}
		case <-c.netPacketConn.pipeDeadline.wait():
			return M.Socksaddr{}, os.ErrDeadlineExceeded
		}
	}

	if c.netPacketConn.disablePipe.Load() {
		return c.packetReadWaiter.WaitReadPacket()
	} else if c.netPacketConn.deadline.Load().IsZero() {
		c.netPacketConn.inRead.Store(true)
		defer c.netPacketConn.inRead.Store(false)
		destination, err = c.packetReadWaiter.WaitReadPacket()
		return
	}

	<-c.netPacketConn.resultCh
	go c.pipeWaitReadPacket()

	return c.WaitReadPacket()
}

func (c *singPacketReadWaiter) pipeWaitReadPacket() {
	destination, err := c.packetReadWaiter.WaitReadPacket()
	result := &singWaitReadResult{}
	result.destination = destination
	result.err = err
	c.netPacketConn.resultCh <- result
}

func (c *singPacketReadWaiter) Upstream() any {
	return c.packetReadWaiter
}
