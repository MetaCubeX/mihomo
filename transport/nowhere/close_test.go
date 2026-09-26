package nowhere

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestMuxResetStopsWrite(t *testing.T) {
	for _, available := range []bool{false, true} {
		t.Run(map[bool]string{false: "exhausted-credit", true: "available-credit"}[available], func(t *testing.T) {
			a, b := net.Pipe()
			incoming := make(chan *muxStream, 1)
			server := newMux(b, func(s *muxStream) { incoming <- s })
			defer server.Close()
			client := newMux(a, nil)
			defer client.Close()
			s, err := client.Open(1)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			peer := <-incoming
			if !available {
				client.mu.Lock()
				s.send = 0
				client.mu.Unlock()
			}
			if _, err = peer.Write([]byte{Ready}); err != nil {
				t.Fatal(err)
			}
			s.SetDeadline(time.Now().Add(3 * time.Second))
			var pending chan error
			if !available {
				pending = make(chan error, 1)
				go func() { _, err := s.Write([]byte{1}); pending <- err }()
			}
			peer.Close()
			data, err := io.ReadAll(s)
			if err != nil || len(data) != 1 || data[0] != Ready {
				t.Fatalf("buffered result after RESET: %v, %v", data, err)
			}
			if _, err = s.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after RESET: %v", err)
			}
			if pending != nil {
				if err := <-pending; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("pending write after RESET: %v", err)
				}
			}
		})
	}
}

func TestPacketFlowClose(t *testing.T) {
	c := testClient(t, testServer(t, false), "udp", "udp", false, false)
	q, err := c.getQUIC(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	m := newMux(a, nil)
	defer m.Close()
	go io.Copy(io.Discard, b)
	s, err := m.Open(123)
	if err != nil {
		t.Fatal(err)
	}
	l := &lane{Conn: s}
	f := &flowConn{reader: l, writer: l, done: make(chan struct{})}
	f.watchCarriers()
	p, err := newPacket(f, 123, "127.0.0.1:53", q, q)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err = p.start(); err != nil {
		t.Fatal(err)
	}
	// The Mux carrier fails while the QUIC carrier is still healthy.
	m.Close()
	p.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err = p.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after carrier failure: %v", err)
	}
	// Synchronize with the asynchronous close before checking route cleanup.
	p.Close()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.routes[123] != nil {
		t.Fatal("closed flow retained its QUIC route")
	}
}

type blockedWriteHandler struct{ release chan struct{} }

func (h blockedWriteHandler) HandleTCP(_ context.Context, c *ServerConn, _ string) {
	defer c.Close()
	if c.HandshakeSuccess() != nil {
		return
	}
	<-h.release
}
func (blockedWriteHandler) HandleUDP(context.Context, *ServerPacketConn, string, net.Addr) {}

func TestQUICCloseUnblocksWrite(t *testing.T) {
	release := make(chan struct{})
	server, err := NewServer(ServerConfig{Password: "secret", TLSConfig: testCertificate(t), Handler: blockedWriteHandler{release}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer close(release)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = server.ServeUDP(udp); err != nil {
		t.Fatal(err)
	}
	c := testClient(t, testEndpoints{udp: udp.LocalAddr().String()}, "udp", "udp", false, false)
	conn, err := c.DialContext(context.Background(), "echo.test:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() { _, err := conn.Write(make([]byte, 32<<20)); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("write finished before Close: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	conn.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded after Close")
		}
	case <-time.After(3 * time.Second):
		conn.SetWriteDeadline(time.Now())
		t.Fatal("Close did not interrupt blocked Write")
	}
}
