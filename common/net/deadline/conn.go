package deadline

import (
	"net"
	"os"
	"time"

	"github.com/metacubex/mihomo/common/atomic"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/network"
)

type connReadResult struct {
	buffer []byte
	err    error
}

type Conn struct {
	network.ExtendedConn
	deadline     atomic.TypedValue[time.Time]
	pipeDeadline pipeDeadline
	disablePipe  atomic.Bool
	inRead       atomic.Bool
	resultCh     chan *connReadResult
}

func IsConn(conn any) bool {
	_, ok := conn.(*Conn)
	return ok
}

func NewConn(conn net.Conn) *Conn {
	c := &Conn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		pipeDeadline: makePipeDeadline(),
		resultCh:     make(chan *connReadResult, 1),
	}
	c.resultCh <- nil
	return c
}

func (c *Conn) Read(p []byte) (n int, err error) {
	select {
	case result := <-c.resultCh:
		if result != nil {
			n = copy(p, result.buffer)
			err = result.err
			if n >= len(result.buffer) {
				c.resultCh <- nil // finish cache read
			} else {
				result.buffer = result.buffer[n:]
				c.resultCh <- result // push back for next call
			}
			return
		} else {
			c.resultCh <- nil
			break
		}
	case <-c.pipeDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}

	if c.disablePipe.Load() {
		return c.ExtendedConn.Read(p)
	} else if c.deadline.Load().IsZero() {
		c.inRead.Store(true)
		defer c.inRead.Store(false)
		return c.ExtendedConn.Read(p)
	}

	<-c.resultCh
	go c.pipeRead(len(p))

	return c.Read(p)
}

func (c *Conn) pipeRead(size int) {
	buffer := make([]byte, size)
	n, err := c.ExtendedConn.Read(buffer)
	buffer = buffer[:n]
	c.resultCh <- &connReadResult{
		buffer: buffer,
		err:    err,
	}
}

func (c *Conn) ReadBuffer(buffer *buf.Buffer) (err error) {
	select {
	case result := <-c.resultCh:
		if result != nil {
			n, _ := buffer.Write(result.buffer)
			err = result.err

			if n >= len(result.buffer) {
				c.resultCh <- nil // finish cache read
			} else {
				result.buffer = result.buffer[n:]
				c.resultCh <- result // push back for next call
			}
			return
		} else {
			c.resultCh <- nil
			break
		}
	case <-c.pipeDeadline.wait():
		return os.ErrDeadlineExceeded
	}

	if c.disablePipe.Load() {
		return c.ExtendedConn.ReadBuffer(buffer)
	} else if c.deadline.Load().IsZero() {
		c.inRead.Store(true)
		defer c.inRead.Store(false)
		return c.ExtendedConn.ReadBuffer(buffer)
	}

	<-c.resultCh
	go c.pipeRead(buffer.FreeLen())

	return c.ReadBuffer(buffer)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.disablePipe.Load() {
		return c.ExtendedConn.SetReadDeadline(t)
	} else if c.inRead.Load() {
		c.disablePipe.Store(true)
		return c.ExtendedConn.SetReadDeadline(t)
	}
	c.deadline.Store(t)
	c.pipeDeadline.set(t)
	return nil
}

func (c *Conn) ReaderReplaceable() bool {
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

func (c *Conn) Upstream() any {
	return c.ExtendedConn
}
