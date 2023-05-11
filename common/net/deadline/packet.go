package deadline

import (
	"net"
	"os"
	"time"

	"github.com/Dreamacro/clash/common/atomic"
	"github.com/Dreamacro/clash/common/net/packet"
)

type readResult struct {
	data []byte
	put  func()
	addr net.Addr
	err  error
}

type PacketConn struct {
	net.PacketConn
	deadline     atomic.TypedValue[time.Time]
	pipeDeadline pipeDeadline
	disablePipe  atomic.Bool
	inRead       atomic.Bool
	resultCh     chan *readResult
}

func NewPacketConn(pc net.PacketConn) net.PacketConn {
	c := &PacketConn{
		PacketConn:   pc,
		pipeDeadline: makePipeDeadline(),
		resultCh:     make(chan *readResult, 1),
	}
	c.resultCh <- nil
	if enhancePacketConn, isEnhance := pc.(packet.EnhancePacketConn); isEnhance {
		return &EnhancePacketConn{
			PacketConn:        c,
			enhancePacketConn: enhancePacketConn,
		}
	}
	return c
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case result := <-c.resultCh:
		if result != nil {
			n = copy(p, result.data)
			addr = result.addr
			err = result.err
			c.resultCh <- nil // finish cache read
			return
		} else {
			c.resultCh <- nil
			break
		}
	case <-c.pipeDeadline.wait():
		return 0, nil, os.ErrDeadlineExceeded
	}

	if c.disablePipe.Load() {
		return c.PacketConn.ReadFrom(p)
	} else if c.deadline.Load().IsZero() {
		c.inRead.Store(true)
		defer c.inRead.Store(false)
		n, addr, err = c.PacketConn.ReadFrom(p)
		return
	}

	<-c.resultCh
	go c.pipeReadFrom(len(p))

	return c.ReadFrom(p)
}

func (c *PacketConn) pipeReadFrom(size int) {
	buffer := make([]byte, size)
	n, addr, err := c.PacketConn.ReadFrom(buffer)
	buffer = buffer[:n]
	c.resultCh <- &readResult{
		data: buffer,
		addr: addr,
		err:  err,
	}
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	if c.disablePipe.Load() {
		return c.PacketConn.SetReadDeadline(t)
	} else if c.inRead.Load() {
		c.disablePipe.Store(true)
		return c.PacketConn.SetReadDeadline(t)
	}
	c.deadline.Store(t)
	c.pipeDeadline.set(t)
	return nil
}

func (c *PacketConn) ReaderReplaceable() bool {
	select {
	case result := <-c.resultCh:
		c.resultCh <- result
		if result != nil {
			return false // cache reading
		} else {
			break
		}
	default:
		return false // pipe reading
	}
	return c.disablePipe.Load() || c.deadline.Load().IsZero()
}

func (c *PacketConn) WriterReplaceable() bool {
	return true
}

func (c *PacketConn) Upstream() any {
	return c.PacketConn
}

func (c *PacketConn) NeedAdditionalReadDeadline() bool {
	return false
}

type EnhancePacketConn struct {
	*PacketConn
	enhancePacketConn packet.EnhancePacketConn
}

func NewEnhancePacketConn(pc packet.EnhancePacketConn) packet.EnhancePacketConn {
	return NewPacketConn(pc).(packet.EnhancePacketConn)
}

func (c *EnhancePacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	select {
	case result := <-c.resultCh:
		if result != nil {
			data = result.data
			put = result.put
			addr = result.addr
			err = result.err
			c.resultCh <- nil // finish cache read
			return
		} else {
			c.resultCh <- nil
			break
		}
	case <-c.pipeDeadline.wait():
		return nil, nil, nil, os.ErrDeadlineExceeded
	}

	if c.disablePipe.Load() {
		return c.enhancePacketConn.WaitReadFrom()
	} else if c.deadline.Load().IsZero() {
		c.inRead.Store(true)
		defer c.inRead.Store(false)
		data, put, addr, err = c.enhancePacketConn.WaitReadFrom()
		return
	}

	<-c.resultCh
	go c.pipeWaitReadFrom()

	return c.WaitReadFrom()
}

func (c *EnhancePacketConn) pipeWaitReadFrom() {
	data, put, addr, err := c.enhancePacketConn.WaitReadFrom()
	c.resultCh <- &readResult{
		data: data,
		put:  put,
		addr: addr,
		err:  err,
	}
}
