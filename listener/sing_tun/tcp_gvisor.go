//go:build with_gvisor

package sing_tun

import (
	"context"
	"net"
	"sync"

	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	M "github.com/metacubex/sing/common/metadata"
)

func (h *ListenerHandler) handleTCPConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	tcpConn, ok := conn.(*gonet.TCPConn)
	if !ok {
		return h.ListenerHandler.NewConnection(ctx, conn, metadata)
	}

	c := &gvisorTCPConn{TCPConn: tcpConn}
	err := h.ListenerHandler.NewConnection(ctx, c, metadata)
	if dialErr := c.dialError(); dialErr != nil {
		// sing-tun aborts the endpoint when NewConnection returns an error.
		// Do not send a graceful FIN before it can send the reset.
		return dialErr
	}
	return err
}

type gvisorTCPConn struct {
	*gonet.TCPConn
	mu  sync.Mutex
	err error
}

func (c *gvisorTCPConn) HandshakeFailure(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
	return nil
}

func (c *gvisorTCPConn) dialError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *gvisorTCPConn) Close() error {
	if c.dialError() != nil {
		return nil
	}
	return c.TCPConn.Close()
}

func (c *gvisorTCPConn) Upstream() any {
	return c.TCPConn
}
