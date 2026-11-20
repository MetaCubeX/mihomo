package nowhere

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockedPacketConn struct {
	net.PacketConn
	blocked atomic.Bool
	release chan struct{}
	once    sync.Once
}

func (p *blockedPacketConn) unblock() { p.once.Do(func() { close(p.release) }) }
func (p *blockedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.blocked.Load() {
		<-p.release
	}
	return p.PacketConn.WriteTo(b, addr)
}

func TestDatagramBackpressureDeadlineAndClose(t *testing.T) {
	c := testClient(t, testUDPServer(t), "udp", "udp", false, false)
	dial := c.config.DialUDP
	var wire *blockedPacketConn
	c.config.DialUDP = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, addr, err := dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		wire = &blockedPacketConn{PacketConn: pc, release: make(chan struct{})}
		t.Cleanup(wire.unblock)
		return wire, addr, nil
	}
	pc, err := c.ListenPacket(context.Background(), "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	defer wire.unblock()
	wire.blocked.Store(true)
	pc.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	written := make(chan error, 1)
	go func() {
		for {
			if _, err := pc.WriteTo(make([]byte, 1000), targetAddr("127.0.0.1:53")); err != nil {
				written <- err
				return
			}
		}
	}()
	select {
	case err := <-written:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DATAGRAM backpressure ignored write deadline")
	}
	pc.SetWriteDeadline(time.Time{})
	go func() { _, err := pc.WriteTo([]byte("pending"), targetAddr("127.0.0.1:53")); written <- err }()
	closed := make(chan struct{})
	go func() { pc.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("CLOSE notification blocked local cleanup")
	}
	select {
	case err := <-written:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt pending datagram")
	}
	if c.quic.conn.Context().Err() != nil {
		t.Fatal("single flow close killed shared QUIC carrier")
	}
	wire.unblock()
	// The shared carrier remains usable by siblings after congestion clears.
	other, err := c.ListenPacket(context.Background(), "127.0.0.1:54")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = other.WriteTo([]byte("ok"), targetAddr("127.0.0.1:54")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if n, _, err := other.ReadFrom(b); err != nil || n != 2 || string(b) != "ok" {
		t.Fatal(n, err, string(b))
	}
}
