package tuic

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type countingClient struct {
	closes      *atomic.Int32
	forceCloses *atomic.Int32
	last        time.Time
}

func (c *countingClient) DialContext(context.Context, *C.Metadata) (net.Conn, error) {
	return nil, nil
}
func (c *countingClient) ListenPacket(context.Context, *C.Metadata) (net.PacketConn, error) {
	return nil, nil
}
func (c *countingClient) OpenStreams() int64         { return 0 }
func (c *countingClient) LastVisited() time.Time     { return c.last }
func (c *countingClient) SetLastVisited(t time.Time) { c.last = t }
func (c *countingClient) Close()                     { c.closes.Add(1) }
func (c *countingClient) ForceClose(error)           { c.forceCloses.Add(1) }

func TestCloseAllForceClosesEveryPooledClientAndEmptiesThePools(t *testing.T) {
	var closes, forceCloses atomic.Int32
	pool := &PoolClient{}
	pool.tcpClients.PushBack(&countingClient{closes: &closes, forceCloses: &forceCloses})
	pool.tcpClients.PushBack(&countingClient{closes: &closes, forceCloses: &forceCloses})
	pool.udpClients.PushBack(&countingClient{closes: &closes, forceCloses: &forceCloses})

	pool.CloseAll(errors.New("test"))

	if got := forceCloses.Load(); got != 3 {
		t.Fatalf("force-closed %d clients, want 3", got)
	}
	if got := closes.Load(); got != 0 {
		t.Fatalf("Close was called %d times; open streams would stay on the dead session", got)
	}
	if pool.tcpClients.Len() != 0 || pool.udpClients.Len() != 0 {
		t.Fatalf("pools not emptied: tcp=%d udp=%d", pool.tcpClients.Len(), pool.udpClients.Len())
	}
	pool.CloseAll(errors.New("test"))
	(&PoolClient{}).CloseAll(errors.New("test"))
}
