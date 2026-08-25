package deadline

import (
	"net"
	"os"
	"time"

	"github.com/metacubex/mihomo/common/atomic"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	"github.com/metacubex/sing/common/network"
)

type connReadResult struct {
	buffer []byte
	err    error
}

type Conn struct {
	network.ExtendedConn
	deadline      atomic.TypedValue[time.Time]
	pipeDeadline  PipeDeadline
	disablePipe   atomic.Bool
	inRead        atomic.Bool
	resultCh      chan *connReadResult
	emulated      bool
	writeDeadline atomic.TypedValue[time.Time]
}

func IsConn(conn any) bool {
	_, ok := conn.(*Conn)
	return ok
}

func NewConn(conn net.Conn) *Conn {
	c := &Conn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		pipeDeadline: MakePipeDeadline(),
		resultCh:     make(chan *connReadResult, 1),
	}
	c.resultCh <- nil
	return c
}

func NewEmulatedConn(conn net.Conn) *Conn {
	c := NewConn(conn)
	c.emulated = true
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
	case <-c.pipeDeadline.Wait():
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
	case <-c.pipeDeadline.Wait():
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
	if !c.emulated {
		if c.disablePipe.Load() {
			return c.ExtendedConn.SetReadDeadline(t)
		} else if c.inRead.Load() {
			c.disablePipe.Store(true)
			return c.ExtendedConn.SetReadDeadline(t)
		}
	}
	c.deadline.Store(t)
	c.pipeDeadline.Set(t)
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	if !c.emulated {
		return c.ExtendedConn.SetDeadline(t)
	}
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if !c.emulated {
		return c.ExtendedConn.SetWriteDeadline(t)
	}
	c.writeDeadline.Store(t)
	return nil
}

func (c *Conn) writeDeadlineExceeded() bool {
	if !c.emulated {
		return false
	}
	deadline := c.writeDeadline.Load()
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

func (c *Conn) Write(p []byte) (n int, err error) {
	if c.writeDeadlineExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	return c.ExtendedConn.Write(p)
}

func (c *Conn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writeDeadlineExceeded() {
		return os.ErrDeadlineExceeded
	}
	return c.ExtendedConn.WriteBuffer(buffer)
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

func (c *Conn) WriterReplaceable() bool {
	return !c.emulated
}

func (c *Conn) Upstream() any {
	return c.ExtendedConn
}
