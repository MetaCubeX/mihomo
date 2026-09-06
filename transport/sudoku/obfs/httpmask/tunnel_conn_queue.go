/*
Copyright (C) 2026 by saba <contact me via issue>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
*/
package httpmask

import (
	"io"
	"net"
	"sync"
	"time"
)

// queuedConn provides a net.Conn-like interface backed by internal channels.
//
// It is used by HTTP tunnel modes (stream/poll) to bridge HTTP request/response bodies to
// a byte-stream API while preserving CloseWrite semantics.
type queuedConn struct {
	rxc    chan []byte
	closed chan struct{}

	writeCh chan []byte
	// writeClosed is closed by CloseWrite to stop accepting new payloads.
	// When closed, Write returns io.ErrClosedPipe, but Read is unaffected.
	writeClosed   chan struct{}
	writeGate     sync.RWMutex
	writeDone     chan struct{}
	writeDoneOnce sync.Once
	writeErr      error
	readEOF       chan struct{}
	readEOFOnce   sync.Once
	readMu        sync.Mutex

	mu         sync.Mutex
	readBuf    []byte
	closeErr   error
	localAddr  net.Addr
	remoteAddr net.Addr
}

const queuedConnPayloadQueueDepth = 64

func newQueuedConn() queuedConn {
	return queuedConn{
		rxc:         make(chan []byte, queuedConnPayloadQueueDepth),
		closed:      make(chan struct{}),
		writeCh:     make(chan []byte, queuedConnPayloadQueueDepth),
		writeClosed: make(chan struct{}),
		writeDone:   make(chan struct{}),
		readEOF:     make(chan struct{}),
		localAddr:   &net.TCPAddr{},
		remoteAddr:  &net.TCPAddr{},
	}
}

func (c *queuedConn) CloseWrite() error {
	if c == nil || c.writeClosed == nil {
		return nil
	}
	c.writeGate.Lock()
	if !isClosedPipeChan(c.writeClosed) {
		close(c.writeClosed)
	}
	c.writeGate.Unlock()

	writeDone := c.writeDone
	closed := c.closed
	if writeDone == nil {
		return nil
	}
	select {
	case <-writeDone:
		return c.completedWriteErr()
	default:
	}
	select {
	case <-writeDone:
		return c.completedWriteErr()
	case <-closed:
		return c.closedErr()
	}
}

func (c *queuedConn) completedWriteErr() error {
	c.mu.Lock()
	err := c.writeErr
	c.mu.Unlock()
	return err
}

func (c *queuedConn) completeWrite(err error) {
	if c == nil || c.writeDone == nil {
		return
	}
	c.mu.Lock()
	if c.writeErr == nil {
		c.writeErr = err
	}
	c.mu.Unlock()
	c.writeDoneOnce.Do(func() { close(c.writeDone) })
}

func (c *queuedConn) markReadEOF() {
	if c == nil || c.readEOF == nil {
		return
	}
	c.readEOFOnce.Do(func() { close(c.readEOF) })
}

func (c *queuedConn) closeWithError(err error) error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil
	default:
		if err == nil {
			err = io.ErrClosedPipe
		}
		if c.closeErr == nil {
			c.closeErr = err
		}
		close(c.closed)
	}
	c.mu.Unlock()
	return nil
}

func (c *queuedConn) closedErr() error {
	c.mu.Lock()
	err := c.closeErr
	c.mu.Unlock()
	if err == nil {
		return io.ErrClosedPipe
	}
	return err
}

func (c *queuedConn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) == 0 {
		select {
		case c.readBuf = <-c.rxc:
		default:
		}
	}
	if len(c.readBuf) == 0 {
		select {
		case c.readBuf = <-c.rxc:
		case <-c.readEOF:
			select {
			case c.readBuf = <-c.rxc:
			default:
				return 0, io.EOF
			}
		case <-c.closed:
			return 0, c.closedErr()
		}
	}
	n = copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *queuedConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	payload := make([]byte, len(b))
	copy(payload, b)
	if c.writeClosed == nil {
		select {
		case c.writeCh <- payload:
			return len(b), nil
		case <-c.closed:
			return 0, c.closedErr()
		}
	}

	c.writeGate.RLock()
	defer c.writeGate.RUnlock()
	select {
	case <-c.closed:
		return 0, c.closedErr()
	default:
	}
	select {
	case <-c.writeClosed:
		return 0, io.ErrClosedPipe
	default:
	}
	select {
	case c.writeCh <- payload:
		return len(b), nil
	case <-c.closed:
		return 0, c.closedErr()
	}
}

func (c *queuedConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *queuedConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *queuedConn) SetDeadline(time.Time) error      { return nil }
func (c *queuedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *queuedConn) SetWriteDeadline(time.Time) error { return nil }
