package httpmask

import (
	"context"
	"net"
	"sync"
)

type tunnelReadiness struct {
	pullReady chan struct{}
	pushReady chan struct{}
	pullOnce  sync.Once
	pushOnce  sync.Once
}

func newTunnelReadiness() *tunnelReadiness {
	return &tunnelReadiness{
		pullReady: make(chan struct{}),
		pushReady: make(chan struct{}),
	}
}

func (r *tunnelReadiness) markPullReady() {
	if r != nil {
		r.pullOnce.Do(func() { close(r.pullReady) })
	}
}

func (r *tunnelReadiness) markPushReady() {
	if r != nil {
		r.pushOnce.Do(func() { close(r.pushReady) })
	}
}

func (r *tunnelReadiness) wait(ctx context.Context, closed <-chan struct{}, closedErr func() error) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, ready := range []<-chan struct{}{r.pullReady, r.pushReady} {
		select {
		case <-ready:
		case <-closed:
			return closedErr()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

type readyTunnelConn struct {
	net.Conn
	waitReady func(context.Context) error
}

func (c *readyTunnelConn) CloseWrite() error {
	if c == nil {
		return nil
	}
	return tryCloseWrite(c.Conn)
}

func (c *readyTunnelConn) CloseRead() error {
	if c == nil {
		return nil
	}
	return tryCloseRead(c.Conn)
}

func (c *readyTunnelConn) waitHTTPMaskReady(ctx context.Context) error {
	if c == nil || c.waitReady == nil {
		return nil
	}
	return c.waitReady(ctx)
}

type tunnelReadyConn interface {
	waitHTTPMaskReady(context.Context) error
}

func wrapReadyTunnelConn(conn net.Conn, waitReady func(context.Context) error) net.Conn {
	if conn == nil || waitReady == nil {
		return conn
	}
	return &readyTunnelConn{Conn: conn, waitReady: waitReady}
}

func WaitTunnelReady(ctx context.Context, conn net.Conn) error {
	if ready, ok := conn.(tunnelReadyConn); ok {
		return ready.waitHTTPMaskReady(ctx)
	}
	return nil
}

func tryCloseRead(target any) error {
	if closer, ok := target.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return nil
}

func tryCloseWrite(target any) error {
	if closer, ok := target.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	if closer, ok := target.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
