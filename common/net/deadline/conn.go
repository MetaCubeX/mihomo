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
	n   int
	err error
}

type Conn struct {
	network.ExtendedConn
	deadline     atomic.TypedValue[time.Time]
	pipeDeadline PipeDeadline
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
		pipeDeadline: MakePipeDeadline(),
		resultCh:     make(chan *connReadResult, 1),
	}
	c.resultCh <- nil
	return c
}

func (c *Conn) Read(p []byte) (n int, err error) {
	buffer := buf.With(p)
	err = c.ReadBuffer(buffer)
	n = buffer.Len()
	return
}

func (c *Conn) ReadBuffer(buffer *buf.Buffer) (err error) {
	for {
		select {
		case result := <-c.resultCh:
			c.resultCh <- nil
			if result != nil {
				buffer.Truncate(buffer.Len() + result.n)
				return result.err
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
		go func(read_buf []byte) {
			n, err := c.ExtendedConn.Read(read_buf)
			c.resultCh <- &connReadResult{
				n:   n,
				err: err,
			}
		}(buffer.FreeBytes())
	}
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.disablePipe.Load() {
		return c.ExtendedConn.SetReadDeadline(t)
	} else if c.inRead.Load() {
		c.disablePipe.Store(true)
		return c.ExtendedConn.SetReadDeadline(t)
	}
	c.deadline.Store(t)
	c.pipeDeadline.Set(t)
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

func (c *Conn) WriterReplaceable() bool {
	return true
}

func (c *Conn) Upstream() any {
	return c.ExtendedConn
}
