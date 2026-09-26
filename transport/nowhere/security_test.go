package nowhere

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestUDPAssociationTargetsAndDeadline(t *testing.T) {
	c := testClient(t, testServer(t, false), "udp", "tcp", true, false)
	p, err := c.ListenPacketAssociation(context.Background(), "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, target := range []string{"127.0.0.1:53", "127.0.0.1:54", "[::1]:55"} {
		_ = p.SetDeadline(time.Now().Add(5 * time.Second))
		payload := []byte(target)
		if _, err = p.WriteTo(payload, targetAddr(target)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 100)
		n, a, err := p.ReadFrom(b)
		if err != nil || a.String() != target || !bytes.Equal(b[:n], payload) {
			t.Fatal(a, err)
		}
	}
	_ = p.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err = p.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("deadline ignored")
	}
	_ = p.SetReadDeadline(time.Time{})
	if _, err = p.WriteTo(nil, targetAddr("127.0.0.1:53")); err != nil {
		t.Fatal(err)
	}
	if n, _, err := p.ReadFrom(make([]byte, 1)); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	p.Close()
	if _, err = p.WriteTo([]byte{1}, targetAddr("127.0.0.1:53")); err == nil {
		t.Fatal("write after close succeeded")
	}
}
func TestSplitInvalidOpenAndConflict(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid-open", true: "metadata-conflict"}[conflict], func(t *testing.T) {
			c := testClient(t, testServer(t, false), "tcp", "udp", false, false)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			up, err := c.acquire(ctx, carrierTLS, 42)
			if err != nil {
				t.Fatal(err)
			}
			defer up.Close()
			h := header{role: open, up: carrierTLS, down: carrierQUIC, id: 42}
			target, _ := targetBytes("echo.test:80")
			if !conflict {
				target[len(target)-1] = 0
			}
			if err = writeFull(up, append(h.bytes(), target...)); err != nil {
				t.Fatal(err)
			}
			down, err := c.acquire(ctx, carrierQUIC, 42)
			if err != nil {
				t.Fatal(err)
			}
			defer down.Close()
			_ = down.SetDeadline(time.Now().Add(5 * time.Second))
			h.role = attach
			if conflict {
				h.kind = 1
			}
			if err = writeFull(down, h.bytes()); err != nil {
				t.Fatal(err)
			}
			want := SetupError(InvalidRequest)
			if conflict {
				want = SetupError(MetadataConflict)
			}
			if err = readResult(down); err != want {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}
func TestSplitAttachFirst(t *testing.T) {
	c := testClient(t, testServer(t, false), "tcp", "udp", true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	down, err := c.acquire(ctx, carrierQUIC, 42)
	if err != nil {
		t.Fatal(err)
	}
	defer down.Close()
	_ = down.SetDeadline(time.Now().Add(5 * time.Second))
	h := header{role: attach, up: carrierTLS, down: carrierQUIC, id: 42}
	if err = writeFull(down, h.bytes()); err != nil {
		t.Fatal(err)
	}
	up, err := c.acquire(ctx, carrierTLS, 42)
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	h.role = open
	target, _ := targetBytes("echo.test:80")
	if err = writeFull(up, append(h.bytes(), target...)); err != nil {
		t.Fatal(err)
	}
	if err = readResult(down); err != nil {
		t.Fatal(err)
	}
	if err = writeFull(up, []byte("split")); err != nil {
		t.Fatal(err)
	}
	var b [5]byte
	if _, err = io.ReadFull(down, b[:]); err != nil || string(b[:]) != "split" {
		t.Fatal(err)
	}
}
func TestAuthenticationFailure(t *testing.T) {
	c := testClient(t, testServer(t, false), "tcp", "tcp", false, false)
	c.key, _ = authKey("wrong")
	if conn, err := c.DialContext(context.Background(), "echo.test:80"); err == nil {
		conn.Close()
		t.Fatal("accepted wrong credential")
	}
}
func TestFragmentReassemblyBounds(t *testing.T) {
	q := &quicSession{routes: make(map[uint32]*packetConn), fragments: make(map[fragmentKey]*assembly)}
	p := &packetConn{readQ: q, packets: make(chan []byte, 64)}
	p.ready.Store(true)
	q.routes[1] = p
	fragment := func(pid uint32, index byte, payload string) []byte {
		b := make([]byte, 12+len(payload))
		binary.BigEndian.PutUint32(b, 1<<30|1)
		binary.BigEndian.PutUint32(b[4:], pid)
		b[8] = index
		b[9] = 2
		binary.BigEndian.PutUint16(b[10:], 4)
		copy(b[12:], payload)
		return b
	}
	for i := uint32(1); i <= 100; i++ {
		q.receive(fragment(i, 1, "cd"))
		q.receive(fragment(i, 0, "ab"))
		select {
		case b := <-p.packets:
			if string(b) != "abcd" {
				t.Fatal(string(b))
			}
			q.queued -= len(b) + 64
		default:
			t.Fatal("completed fragment slots were not reusable")
		}
	}
	if q.assembled != 0 || len(q.fragments) != 0 {
		t.Fatal("reassembly leaked completed packets")
	}
	q.receive(fragment(101, 0, "ab"))
	q.receive(fragment(101, 0, "xy"))
	q.receive(fragment(101, 1, "cd"))
	if len(p.packets) != 0 {
		t.Fatal("delivered conflicting duplicate")
	}
	q.expireFragments(time.Now().Add(11 * time.Second))
	for i := uint32(1); i <= 100; i++ {
		q.receive(fragment(i, 0, "ab"))
	}
	if len(q.fragments) != 64 {
		t.Fatal("unbounded slots", len(q.fragments))
	}
	q.expireFragments(time.Now().Add(11 * time.Second))
	if q.assembled != 0 || len(q.fragments) != 0 {
		t.Fatal("TTL did not release fragments")
	}
	p.ready.Store(false)
	q.receive([]byte{0, 0, 0, 1, 42})
	if len(p.packets) != 0 {
		t.Fatal("queued pre-READY payload")
	}
}
func TestForwardingBudget(t *testing.T) {
	for incoming := byte(0); incoming <= 7; incoming++ {
		ctx, err := ForwardContext(context.Background(), incoming)
		if incoming == 1 {
			if err != SetupError(FlowLimit) {
				t.Fatal(err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		want := incoming - 1
		if incoming == 0 {
			want = 7
		}
		if Hops(ctx) != want {
			t.Fatal(Hops(ctx), want)
		}
	}
}

func TestUOTTruncatedFrames(t *testing.T) {
	for _, wire := range [][]byte{{0}, {0, 2, 1}} {
		local, peer := net.Pipe()
		l := &lane{Conn: local}
		p, err := newPacket(&flowConn{reader: l, writer: l}, 1, "127.0.0.1:53", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = writeFull(peer, wire); peer.Close() }()
		n, _, readErr := p.ReadFrom(make([]byte, 10))
		err = readErr
		p.Close()
		if n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
	}
}

func TestMuxRejectsMalformedFrames(t *testing.T) {
	for _, wire := range [][]byte{{0, 0, 0, 0, 0, 0, 1}, {2, 0, 0, 0, 0, 0, 1}, {2, 0, 1, 0, 0, 0, 0, 42}, {1, 0, 0, 128, 0, 0, 1}, {3, 0, 0, 0, 0, 0, 0}, {3, 255, 255, 0, 0, 0, 0}, {5, 0, 1, 0, 0, 0, 1}} {
		local, peer := net.Pipe()
		m := newMux(local, nil)
		go func() { _ = writeFull(peer, wire) }()
		select {
		case <-m.done:
		case <-time.After(time.Second):
			t.Fatal("malformed frame did not close carrier")
		}
		peer.Close()
		m.Close()
	}
}

func TestMuxCloseDuringWritePreservesSiblings(t *testing.T) {
	local, peer := net.Pipe()
	server := newMux(peer, func(s *muxStream) { defer s.Close(); _, _ = io.Copy(s, s) })
	defer server.Close()
	client := newMux(local, nil)
	defer client.Close()
	stable, err := client.Open(1)
	if err != nil {
		t.Fatal(err)
	}
	defer stable.Close()
	_ = stable.SetDeadline(time.Now().Add(10 * time.Second))
	for id := uint32(2); id < 102; id++ {
		s, err := client.Open(id)
		if err != nil {
			t.Fatal(err)
		}
		written := make(chan struct{})
		go func() { _, _ = s.Write(make([]byte, 128<<10)); close(written) }()
		s.Close()
		select {
		case <-written:
		case <-time.After(time.Second):
			t.Fatal("close did not interrupt write")
		}
		if _, err = stable.Write([]byte{42}); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		if _, err = io.ReadFull(stable, b[:]); err != nil || b[0] != 42 {
			t.Fatalf("sibling failed: %v", err)
		}
	}
}
func TestCarrierFailureClosesSplitPeer(t *testing.T) {
	c := testClient(t, testServer(t, false), "tcp", "udp", false, false)
	conn, err := c.DialContext(context.Background(), "echo.test:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c.quic.Close()
	f := conn.(*flowConn)
	select {
	case <-f.done:
	case <-time.After(3 * time.Second):
		t.Fatal("split lane survived failed carrier")
	}
	// done signals cancellation before Close tears down both lanes. Join the
	// watcher-triggered Close (via sync.Once) before inspecting its effects.
	_ = f.Close()
	if _, err = f.writer.Write([]byte{1}); err == nil {
		t.Fatal("TLS sibling remained open")
	}
	exerciseTCP(t, c, "echo.test:80", 1024)
}

func TestMixFallbackBeforeSetupOnly(t *testing.T) {
	for _, failed := range []string{"tcp", "udp"} {
		t.Run(failed, func(t *testing.T) {
			c := testClient(t, testServer(t, false), "mix", "mix", false, false)
			if failed == "tcp" {
				c.config.DialTCP = func(context.Context) (net.Conn, error) { return nil, errors.New("TCP unavailable") }
			} else {
				c.route.Store(1)
				c.config.DialUDP = func(context.Context) (net.PacketConn, net.Addr, error) {
					return nil, nil, errors.New("UDP unavailable")
				}
			}
			exerciseTCP(t, c, "echo.test:80", 1024)
			c.mu.Lock()
			id := c.nextID
			c.mu.Unlock()
			if id != 2 {
				t.Fatal("fallback did not use a fresh flow ID", id)
			}
		})
	}
	c := testClient(t, testServer(t, false), "mix", "mix", false, false)
	c.key, _ = authKey("wrong")
	called := false
	c.config.DialUDP = func(context.Context) (net.PacketConn, net.Addr, error) {
		called = true
		return nil, nil, errors.New("must not retry after setup")
	}
	if conn, err := c.DialContext(context.Background(), "echo.test:80"); err == nil {
		conn.Close()
		t.Fatal("wrong authentication accepted")
	}
	if called {
		t.Fatal("fell back after committing setup")
	}
}

func TestQUICReplacementRejectsPendingPair(t *testing.T) {
	address, s := testServerInstance(t, false)
	c := testClient(t, address, "udp", "tcp", false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	up, err := c.acquire(ctx, carrierQUIC, 42)
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	h := header{role: open, up: carrierQUIC, down: carrierTLS, id: 42}
	target, _ := targetBytes("echo.test:80")
	if err = writeFull(up, append(h.bytes(), target...)); err != nil {
		t.Fatal(err)
	}
	for {
		s.mu.Lock()
		pending := s.claims[claimKey{c.session, 42}] != nil
		s.mu.Unlock()
		if pending {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("OPEN never reached server")
		case <-time.After(time.Millisecond):
		}
	}
	replacement := testClient(t, address, "udp", "tcp", false, false)
	replacement.session = c.session
	if _, err = replacement.getQUIC(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-up.q.conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("old QUIC session was not replaced")
	}
	down, err := replacement.acquire(ctx, carrierTLS, 42)
	if err != nil {
		t.Fatal(err)
	}
	defer down.Close()
	_ = down.SetDeadline(time.Now().Add(3 * time.Second))
	h.role = attach
	if err = writeFull(down, h.bytes()); err != nil {
		t.Fatal(err)
	}
	if err = readResult(down); err != SetupError(SessionReplaced) {
		t.Fatalf("got %v", err)
	}
}
func TestHalfClose(t *testing.T) {
	for _, route := range [][2]string{{"tcp", "tcp"}, {"tcp", "udp"}, {"udp", "tcp"}, {"udp", "udp"}} {
		t.Run(route[0]+"-"+route[1], func(t *testing.T) {
			c := testClient(t, testServer(t, false), route[0], route[1], true, false)
			conn, err := c.DialContext(context.Background(), "echo.test:80")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, err = conn.Write([]byte("half-close"))
			if err != nil {
				t.Fatal(err)
			}
			if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(conn)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
			if string(b) != "half-close" {
				t.Fatal(string(b))
			}
		})
	}
}
