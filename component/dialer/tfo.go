package dialer

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/tfo-go"
)

var DisableTFO = false

const (
	tfoReady uint32 = 1 << iota
	tfoClosed
)

type tfoConn struct {
	// Written once under mu, then immutable. The ready bit publishes it to
	// readers without a boxed interface allocation or a steady-state mutex.
	connection net.Conn
	mu         sync.Mutex
	dialMu     sync.Mutex
	flags      atomic.Uint32
	dialErr    error
	dialed     chan struct{}
	cancel     context.CancelFunc
	ctx        context.Context
	dialFn     func(ctx context.Context, earlyData []byte) (net.Conn, error)
}

func (c *tfoConn) state() (net.Conn, bool) {
	flags := c.flags.Load()
	if flags&tfoReady != 0 {
		return c.connection, flags&tfoClosed != 0
	}
	return nil, flags&tfoClosed != 0
}

// Only the first writer supplies early data. Network I/O never holds mu, so
// Close can cancel an in-progress dial and retire a late successful socket.
func (c *tfoConn) dial(earlyData []byte) (conn net.Conn, consumed bool, err error) {
	c.dialMu.Lock()
	defer c.dialMu.Unlock()
	conn, closed := c.state()
	if closed {
		return nil, false, io.ErrClosedPipe
	}
	if conn != nil || c.dialErr != nil {
		return conn, false, c.dialErr
	}
	if err = c.ctx.Err(); err != nil {
		return nil, false, err
	}
	conn, err = c.dialFn(c.ctx, earlyData)
	c.mu.Lock()
	flags := c.flags.Load()
	closed = flags&tfoClosed != 0
	if err == nil && c.ctx.Err() != nil {
		err = c.ctx.Err()
	}
	if err == nil && !closed {
		c.connection = conn
		c.flags.Store(flags | tfoReady)
	} else {
		if closed {
			err = io.ErrClosedPipe
		}
		c.dialErr = err
	}
	c.mu.Unlock()
	close(c.dialed)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, false, err
	}
	return conn, true, nil
}

func (c *tfoConn) Read(b []byte) (n int, err error) {
	conn, closed := c.state()
	if closed {
		return 0, io.ErrClosedPipe
	}
	if conn == nil {
		select {
		case <-c.ctx.Done():
			return 0, io.ErrUnexpectedEOF
		case <-c.dialed:
		}
		conn, closed = c.state()
		if closed {
			return 0, io.ErrClosedPipe
		}
		// dialErr is published before dialed is closed.
		if c.dialErr != nil {
			return 0, c.dialErr
		}
	}
	return conn.Read(b)
}

func (c *tfoConn) Write(b []byte) (n int, err error) {
	conn, closed := c.state()
	if closed {
		return 0, io.ErrClosedPipe
	}
	if conn == nil {
		var consumed bool
		conn, consumed, err = c.dial(b)
		if err != nil {
			return 0, err
		}
		if consumed {
			return len(b), nil
		}
	}

	return conn.Write(b)
}

func (c *tfoConn) Close() error {
	c.mu.Lock()
	flags := c.flags.Load()
	if flags&tfoClosed != 0 {
		c.mu.Unlock()
		return nil
	}
	c.flags.Store(flags | tfoClosed)
	conn, _ := c.state()
	c.mu.Unlock()
	c.cancel()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

func (c *tfoConn) LocalAddr() net.Addr {
	conn, _ := c.state()
	if conn == nil {
		return &net.TCPAddr{}
	}
	return conn.LocalAddr()
}

func (c *tfoConn) RemoteAddr() net.Addr {
	conn, _ := c.state()
	if conn == nil {
		return &net.TCPAddr{}
	}
	return conn.RemoteAddr()
}

func (c *tfoConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *tfoConn) SetReadDeadline(t time.Time) error {
	conn, _ := c.state()
	if conn == nil {
		return nil
	}
	return conn.SetReadDeadline(t)
}

func (c *tfoConn) SetWriteDeadline(t time.Time) error {
	conn, _ := c.state()
	if conn == nil {
		return nil
	}
	return conn.SetWriteDeadline(t)
}

func (c *tfoConn) Upstream() any {
	conn, _ := c.state()
	return conn
}

func (c *tfoConn) NeedAdditionalReadDeadline() bool {
	conn, _ := c.state()
	return conn == nil
}

func (c *tfoConn) NeedHandshake() bool {
	conn, _ := c.state()
	return conn == nil
}

func (c *tfoConn) ReaderReplaceable() bool {
	conn, _ := c.state()
	return conn != nil
}

func (c *tfoConn) WriterReplaceable() bool {
	conn, _ := c.state()
	return conn != nil
}

func dialTFO(ctx context.Context, netDialer net.Dialer, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTCPTimeout)
	dialer := tfo.Dialer{Dialer: netDialer, DisableTFO: false}
	return &tfoConn{
		dialed: make(chan struct{}),
		cancel: cancel,
		ctx:    ctx,
		dialFn: func(ctx context.Context, earlyData []byte) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address, earlyData)
		},
	}, nil
}
