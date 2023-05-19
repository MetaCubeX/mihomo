package deadline

import (
	"net"
	"os"

	"github.com/Dreamacro/clash/common/net/packet"
)

type EnhancePacketConn struct {
	*NetPacketConn
	enhancePacketConn
}

var _ packet.EnhancePacketConn = (*EnhancePacketConn)(nil)

func NewEnhancePacketConn(pc packet.EnhancePacketConn) packet.EnhancePacketConn {
	return NewNetPacketConn(pc).(packet.EnhancePacketConn)
}

type enhanceReadResult struct {
	put func()
}

type enhancePacketConn struct {
	netPacketConn     *NetPacketConn
	enhancePacketConn packet.EnhancePacketConn
}

func (c *enhancePacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	select {
	case result := <-c.netPacketConn.resultCh:
		if result != nil {
			data = result.data
			put = result.put
			addr = result.addr
			err = result.err
			c.netPacketConn.resultCh <- nil // finish cache read
			return
		} else {
			c.netPacketConn.resultCh <- nil
			break
		}
	case <-c.netPacketConn.pipeDeadline.wait():
		return nil, nil, nil, os.ErrDeadlineExceeded
	}

	if c.netPacketConn.disablePipe.Load() {
		return c.enhancePacketConn.WaitReadFrom()
	} else if c.netPacketConn.deadline.Load().IsZero() {
		c.netPacketConn.inRead.Store(true)
		defer c.netPacketConn.inRead.Store(false)
		data, put, addr, err = c.enhancePacketConn.WaitReadFrom()
		return
	}

	<-c.netPacketConn.resultCh
	go c.pipeWaitReadFrom()

	return c.WaitReadFrom()
}

func (c *enhancePacketConn) pipeWaitReadFrom() {
	data, put, addr, err := c.enhancePacketConn.WaitReadFrom()
	c.netPacketConn.resultCh <- &readResult{
		data: data,
		enhanceReadResult: enhanceReadResult{
			put: put,
		},
		addr: addr,
		err:  err,
	}
}
