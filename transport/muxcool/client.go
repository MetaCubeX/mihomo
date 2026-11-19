// Package muxcool implements the client side of Mux.Cool, the multiplexing
// protocol used by v2ray/xray (https://xtls.github.io/development/protocols/muxcool.html).
//
// Only TCP sub connections are multiplexed here, UDP is expected to be carried
// by XUDP which already uses the same frame format on its own connection.
package muxcool

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	M "github.com/metacubex/sing/common/metadata"
)

const (
	// DefaultConcurrency is the default number of sub connections sharing one connection.
	DefaultConcurrency = 8
	// MaxConcurrency is the biggest concurrency accepted by the protocol peers.
	MaxConcurrency = 1024
	// maxSessionsPerConn is how many sub connections a connection may carry
	// during its whole lifetime, sub connection ids are never reused.
	maxSessionsPerConn = 128
	// idleTimeout is how long a connection without any sub connection is kept open.
	idleTimeout = 16 * time.Second
)

var ErrClientClosed = errors.New("muxcool: client closed")

// DialFunc opens a new connection to the server which has already been
// prepared to carry Mux.Cool frames (i.e. the proxy request with the mux
// command will be sent with the first write).
type DialFunc func(ctx context.Context) (net.Conn, error)

type Client struct {
	dial        DialFunc
	concurrency int

	access   sync.Mutex
	sessions []*session
	closed   bool
}

func NewClient(dial DialFunc, concurrency int) *Client {
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency > MaxConcurrency {
		concurrency = MaxConcurrency
	}
	return &Client{
		dial:        dial,
		concurrency: concurrency,
	}
}

// DialContext opens a new TCP sub connection to destination.
func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if stream, err := c.openOnExisting(destination); stream != nil || err != nil {
		return stream, err
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	s := newSession(conn, c.concurrency)
	if ctx.Done() != nil {
		// don't let a canceled dial hang on a blocked handshake write
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				s.close(ctx.Err())
			case <-done:
			}
		}()
	}
	// open before publishing the session so nobody can steal our slot
	stream, err := s.open(destination)
	if err != nil {
		s.close(err)
		return nil, err
	}

	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		s.close(ErrClientClosed)
		return nil, ErrClientClosed
	}
	c.sessions = append(c.sessions, s)
	c.access.Unlock()
	return stream, nil
}

func (c *Client) openOnExisting(destination M.Socksaddr) (net.Conn, error) {
	// note: returns an untyped nil conn when no session has room
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil, ErrClientClosed
	}
	// drop dead sessions
	alive := c.sessions[:0]
	for _, s := range c.sessions {
		if !s.isClosed() {
			alive = append(alive, s)
		}
	}
	for i := len(alive); i < len(c.sessions); i++ {
		c.sessions[i] = nil
	}
	c.sessions = alive
	sessions := append([]*session(nil), alive...)
	c.access.Unlock()

	for _, s := range sessions {
		stream, err := s.open(destination)
		if err == nil {
			return stream, nil
		}
		// errSessionFull or a broken session, try the next one
	}
	return nil, nil
}

func (c *Client) Close() error {
	c.access.Lock()
	sessions := c.sessions
	c.sessions = nil
	c.closed = true
	c.access.Unlock()
	for _, s := range sessions {
		s.close(ErrClientClosed)
	}
	return nil
}
