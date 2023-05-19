package deadline

import (
	"os"

	"github.com/Dreamacro/clash/common/net/packet"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
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
}

type singPacketConn struct {
	netPacketConn  *NetPacketConn
	singPacketConn packet.SingPacketConn
}

func (c *singPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case result := <-c.netPacketConn.resultCh:
		if result != nil {
			destination = result.destination
			err = result.err
			buffer.Resize(result.buffer.Start(), 0)
			n := copy(buffer.FreeBytes(), result.buffer.Bytes())
			buffer.Truncate(n)
			result.buffer.Advance(n)
			if result.buffer.IsEmpty() {
				result.buffer.Release()
			}
			c.netPacketConn.resultCh <- nil // finish cache read
			return
		} else {
			c.netPacketConn.resultCh <- nil
			break
		}
	case <-c.netPacketConn.pipeDeadline.wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
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
	go c.pipeReadPacket(buffer.Cap(), buffer.Start())

	return c.ReadPacket(buffer)
}

func (c *singPacketConn) pipeReadPacket(bufLen int, bufStart int) {
	buffer := buf.NewSize(bufLen)
	buffer.Advance(bufStart)
	destination, err := c.singPacketConn.ReadPacket(buffer)
	c.netPacketConn.resultCh <- &readResult{
		singReadResult: singReadResult{
			buffer:      buffer,
			destination: destination,
		},
		err: err,
	}
}

func (c *singPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.singPacketConn.WritePacket(buffer, destination)
}
