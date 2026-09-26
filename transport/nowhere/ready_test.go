package nowhere

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

type readyWriteConn struct {
	net.Conn
	afterWrite func()
}

func (c *readyWriteConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 && c.afterWrite != nil {
		f := c.afterWrite
		c.afterWrite = nil
		f()
	}
	return n, err
}

type readyTestHandler struct {
	echoHandler
	observed chan bool
}

func (h readyTestHandler) HandleUDP(ctx context.Context, p *ServerPacketConn, target string, source net.Addr) {
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], p.id)
	p.readQ.receive(frame[:])
	preSetupDropped := len(p.packets) == 0
	// A peer may process READY before the server's Write returns. Dispatch a
	// datagram at precisely that boundary, without relying on scheduling.
	p.flow.writer.Conn = &readyWriteConn{Conn: p.flow.writer.Conn, afterWrite: func() {
		p.readQ.receive(frame[:])
		h.observed <- preSetupDropped && len(p.packets) == 1
	}}
	h.echoHandler.HandleUDP(ctx, p, target, source)
}

type failedReadyConn struct {
	net.Conn
	packet *packetConn
}

func (c *failedReadyConn) Write([]byte) (int, error) {
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], c.packet.id)
	c.packet.readQ.receive(frame[:])
	return 0, net.ErrClosed
}

type failedReadyHandler struct {
	echoHandler
	observed chan bool
}

func (h failedReadyHandler) HandleUDP(_ context.Context, p *ServerPacketConn, _ string, _ net.Addr) {
	p.flow.writer.Conn = &failedReadyConn{Conn: p.flow.writer.Conn, packet: p.packetConn}
	err := p.HandshakeSuccess()
	q := p.readQ
	q.mu.Lock()
	_, registered := q.routes[p.id]
	clean := !registered && q.queued == 0 && q.assembled == 0 && len(p.packets) == 0
	q.mu.Unlock()
	h.observed <- errors.Is(err, net.ErrClosed) && clean && !p.ready.Load()
}

func TestUDPReadyFailureCleanup(t *testing.T) {
	observed := make(chan bool, 1)
	address, _ := testServerWithHandler(t, false, failedReadyHandler{observed: observed})
	c := testClient(t, address, "udp", "tcp", false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if p, err := c.ListenPacket(ctx, "127.0.0.1:53"); err == nil {
		p.Close()
		t.Fatal("accepted failed READY write")
	}
	select {
	case clean := <-observed:
		if !clean {
			t.Fatal("failed READY left an active route or queued payload")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestClosedPacketCannotActivate(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	l := &lane{Conn: a}
	f := &flowConn{reader: l, writer: l, done: make(chan struct{})}
	p, err := newPacket(f, 1, "127.0.0.1:53", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	if err = p.start(); !errors.Is(err, net.ErrClosed) || p.ready.Load() {
		t.Fatalf("closed flow reactivated: %v", err)
	}
}

func TestUDPReadyPublication(t *testing.T) {
	observed := make(chan bool, 1)
	address, _ := testServerWithHandler(t, false, readyTestHandler{observed: observed})
	c := testClient(t, address, "udp", "tcp", false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := c.ListenPacket(ctx, "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	select {
	case accepted := <-observed:
		if !accepted {
			t.Fatal("dropped datagram after READY was published but before Write returned")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_ = p.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := p.ReadFrom(make([]byte, 1)); err != nil || n != 0 {
		t.Fatalf("empty datagram reply: n=%d, err=%v", n, err)
	}
}
