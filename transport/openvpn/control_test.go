package openvpn

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type memoryPacketIO struct {
	in     <-chan []byte
	out    chan<- []byte
	closed chan struct{}
	once   sync.Once
}

func newMemoryPacketPair() (*memoryPacketIO, *memoryPacketIO) {
	aToB := make(chan []byte, 16)
	bToA := make(chan []byte, 16)
	a := &memoryPacketIO{in: bToA, out: aToB, closed: make(chan struct{})}
	b := &memoryPacketIO{in: aToB, out: bToA, closed: make(chan struct{})}
	return a, b
}

func (m *memoryPacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.closed:
		return nil, net.ErrClosed
	case packet := <-m.in:
		return cloneBytes(packet), nil
	}
}

func (m *memoryPacketIO) WritePacket(ctx context.Context, packet []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.closed:
		return net.ErrClosed
	case m.out <- cloneBytes(packet):
		return nil
	}
}

func (m *memoryPacketIO) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func (m *memoryPacketIO) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (m *memoryPacketIO) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

func newTestChannels(t *testing.T) (*ControlChannel, *ControlChannel) {
	t.Helper()
	clientIO, serverIO := newMemoryPacketPair()
	clientCrypt, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	serverCrypt, err := NewTLSCrypt(testStaticKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))

	client := NewControlChannel(clientIO, clientCrypt, clientID)
	server := NewControlChannel(serverIO, serverCrypt, serverID)
	client.clock = func() time.Time { return time.Unix(1714567890, 0) }
	server.clock = func() time.Time { return time.Unix(1714567891, 0) }
	return client, server
}

// TestCheckReplayAntiReplay verifies the protected-control anti-replay window
// accepts advancing ids, rejects replays and stale/timestamp-backtracking
// packets, and resets on a new second.
// TestRecvPendingBounded verifies the out-of-order receive buffer does not
// grow without bound: packets whose message ID falls outside
// [recvMessage, recvMessage+reliableCapacity) are not buffered, and the
// buffer stops filling once it holds reliableCapacity packets.
func TestRecvPendingBounded(t *testing.T) {
	const base = uint32(100)
	// In-window ids are storable up to the capacity.
	for i := uint32(1); i < reliableCapacity; i++ {
		if !recvWindowOK(base, base+i, int(i-1)) {
			t.Fatalf("in-window id %d refused", base+i)
		}
	}
	// At capacity, further ids are refused even if in-window.
	if recvWindowOK(base, base+1, reliableCapacity) {
		t.Fatal("buffered==capacity should refuse")
	}
	// Past the window refused.
	if recvWindowOK(base, base+reliableCapacity, 0) {
		t.Fatal("id at window edge accepted")
	}
	if recvWindowOK(base, base+reliableCapacity+1, 0) {
		t.Fatal("id past window accepted")
	}
	// Below recvMessage refused (handled as replay earlier, but window must
	// not accept it).
	if recvWindowOK(base, base-1, 0) {
		t.Fatal("id below recvMessage accepted")
	}
}

func TestCheckReplayAntiReplay(t *testing.T) {
	c := &ControlChannel{}
	// First packet initializes the window.
	if err := c.checkReplayLocked(1, 1000); err != nil {
		t.Fatalf("first packet rejected: %v", err)
	}
	// Advancing id accepted.
	for _, id := range []uint32{2, 3, 5} {
		if err := c.checkReplayLocked(id, 1000); err != nil {
			t.Fatalf("advancing id %d rejected: %v", id, err)
		}
	}
	// Out-of-order within window accepted.
	if err := c.checkReplayLocked(4, 1000); err != nil {
		t.Fatalf("out-of-order id 4 rejected: %v", err)
	}
	// Exact replay rejected.
	if err := c.checkReplayLocked(4, 1000); err == nil {
		t.Fatal("replayed id 4 accepted")
	}
	// Stale id beyond window rejected.
	if err := c.checkReplayLocked(1, 1000); err == nil {
		t.Fatal("stale id 1 accepted")
	}
	// Timestamp backtrack rejected.
	if err := c.checkReplayLocked(10, 999); err == nil {
		t.Fatal("timestamp backtrack accepted")
	}
	// New second resets and accepts.
	if err := c.checkReplayLocked(1, 1001); err != nil {
		t.Fatalf("new second id 1 rejected: %v", err)
	}
	if err := c.checkReplayLocked(1, 1001); err == nil {
		t.Fatal("replay after reset accepted")
	}
	// resetReplayLocked seeds a fresh window.
	c.resetReplayLocked(1, 2000)
	if err := c.checkReplayLocked(1, 2000); err == nil {
		t.Fatal("duplicate of seed id accepted")
	}
	if err := c.checkReplayLocked(2, 2000); err != nil {
		t.Fatalf("advancing id after reset rejected: %v", err)
	}
}

func TestControlChannelResetAndAck(t *testing.T) {
	client, server := newTestChannels(t)

	if err := client.SendReset(context.Background()); err != nil {
		t.Fatal(err)
	}
	packet, err := server.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if packet.Opcode != PControlHardResetClientV2 || packet.MessageID != 0 {
		t.Fatalf("unexpected reset packet: %s/%d", packet.Opcode, packet.MessageID)
	}
	if packetID := client.sendPacketID; packetID != 1 {
		t.Fatalf("unexpected first tls-crypt packet id: %d", packetID)
	}
	if server.RemoteSessionID() != client.LocalSessionID() {
		t.Fatalf("server did not learn client session id")
	}

	if err := server.SendAck(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.Read(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline after consuming pure ack, got %v", err)
	}
	if client.PendingMessages() != 0 {
		t.Fatalf("expected client reset to be acked, pending=%d", client.PendingMessages())
	}
}

func TestControlConnCarriesTLSBytes(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())

	clientConn := NewControlConn(client)
	serverConn := NewControlConn(server)

	errCh := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("client tls record"))
		errCh <- err
	}()

	buf := make([]byte, 64)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "client tls record" {
		t.Fatalf("unexpected payload: %q", got)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.Read(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline after consuming pure ack, got %v", err)
	}
	if client.PendingMessages() != 0 {
		t.Fatalf("expected client message to be acked, pending=%d", client.PendingMessages())
	}
}

func TestControlChannelReordersReliableMessages(t *testing.T) {
	packets := make(chan []byte, 4)
	acks := make(chan []byte, 4)
	io := &memoryPacketIO{in: packets, out: acks, closed: make(chan struct{})}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	server := NewControlChannel(io, nil, serverID)

	second, err := (ControlPacket{
		Opcode:       PControlV1,
		LocalSession: clientID,
		MessageID:    1,
		Payload:      []byte("second"),
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	first, err := (ControlPacket{
		Opcode:       PControlV1,
		LocalSession: clientID,
		MessageID:    0,
		Payload:      []byte("first"),
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	packets <- second
	packets <- first

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packet, err := server.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if packet.MessageID != 0 || string(packet.Payload) != "first" {
		t.Fatalf("unexpected first delivered packet: id=%d payload=%q", packet.MessageID, packet.Payload)
	}
	packet, err = server.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if packet.MessageID != 1 || string(packet.Payload) != "second" {
		t.Fatalf("unexpected second delivered packet: id=%d payload=%q", packet.MessageID, packet.Payload)
	}
}

func TestClientWaitServerResetRetransmitsUDP(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))

	clientControl := NewControlChannel(clientIO, nil, clientID)
	serverControl := NewControlChannel(serverIO, nil, serverID)
	client := &Client{
		config:  &ClientConfig{Proto: ProtoUDP},
		control: clientControl,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := clientControl.SendReset(ctx); err != nil {
		t.Fatal(err)
	}

	waitErr := make(chan error, 1)
	go func() {
		waitErr <- client.waitServerReset(ctx)
	}()

	// Drop the first raw reset; the client retransmits on the next
	// ControlRetransmitDelay once waitServerReset is running.
	first, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pkt, _, _, err := DecodeControlPacket(nil, first)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Opcode != PControlHardResetClientV2 {
		t.Fatalf("unexpected first reset opcode: %s", pkt.Opcode)
	}

	second, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pkt, _, _, err = DecodeControlPacket(nil, second)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Opcode != PControlHardResetClientV2 || pkt.MessageID != 0 {
		t.Fatalf("unexpected retransmitted reset: %s msg=%d", pkt.Opcode, pkt.MessageID)
	}

	// Ack the retransmitted reset, then respond with the server hard reset.
	serverControl.QueueAck(0)
	if err := serverControl.SendAck(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := serverControl.Send(ctx, PControlHardResetServerV2, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-waitErr; err != nil {
		t.Fatal(err)
	}
	if clientControl.PendingMessages() != 0 {
		t.Fatalf("expected client reset to be acked, pending=%d", clientControl.PendingMessages())
	}
}

func TestClientClosesOnSoftReset(t *testing.T) {
	for _, name := range []string{"plain", "tls-auth", "tls-crypt"} {
		t.Run(name, func(t *testing.T) {
			var (
				config      ClientConfig
				serverCrypt ControlCryptor
				err         error
			)
			switch name {
			case "tls-auth":
				config.TLSAuthKey = testStaticKey()
				config.KeyDirection = "1"
				serverCrypt, err = NewTLSAuth(testStaticKey(), "0")
			case "tls-crypt":
				config.TLSCryptKey = testStaticKey()
				serverCrypt, err = NewTLSCrypt(testStaticKey(), false)
			}
			if err != nil {
				t.Fatal(err)
			}

			clientIO, serverIO := newMemoryPacketPair()
			client, err := NewClient(&config, clientIO)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var serverID SessionID
			copy(serverID[:], []byte("server01"))
			client.control.SetRemoteSessionID(serverID)
			go client.watchControl()
			serverControl := NewControlChannel(serverIO, serverCrypt, serverID)
			serverControl.SetRemoteSessionID(client.control.LocalSessionID())

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := client.control.Send(ctx, PControlV1, []byte("client control")); err != nil {
				t.Fatal(err)
			}
			packet, err := serverControl.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if string(packet.Payload) != "client control" {
				t.Fatalf("unexpected client control payload: %q", packet.Payload)
			}
			if err := serverControl.SendAck(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := serverControl.Send(ctx, PControlV1, nil); err != nil {
				t.Fatal(err)
			}
			if err := serverIO.WritePacket(ctx, []byte{opcodeKeyID(PControlSoftResetV1, 1)}); err != nil {
				t.Fatal(err)
			}
			softReset, err := (ControlPacket{
				Opcode:       PControlSoftResetV1,
				KeyID:        1,
				LocalSession: serverID,
				MessageID:    0,
			}).Encode(serverCrypt, 3, 1714567890)
			if err != nil {
				t.Fatal(err)
			}
			if err := serverIO.WritePacket(ctx, softReset); err != nil {
				t.Fatal(err)
			}
			// With the rekey fix, the client attempts TLS renegotiation on
			// soft reset. Since no real TLS connection was established in
			// this unit test (tlsConn is nil), renegotiate() should fail
			// and the client should close.
			select {
			case <-client.mux.done:
			case <-ctx.Done():
				t.Fatal("client did not close after soft reset renegotiation failure")
			}
			if client.control.recvMessage != 1 {
				t.Fatalf("soft reset changed the old epoch receive sequence: %d", client.control.recvMessage)
			}
			if client.control.PendingMessages() != 0 {
				t.Fatalf("expected server ack to clear client pending messages: %d", client.control.PendingMessages())
			}

			ackCtx, ackCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer ackCancel()
			_, err = serverControl.Read(ackCtx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline after consuming client ack, got %v", err)
			}
			if serverControl.PendingMessages() != 0 {
				t.Fatalf("expected client to ack ordinary control message: %d", serverControl.PendingMessages())
			}
		})
	}
}

func TestClientControlWatcherIgnoresInvalidPackets(t *testing.T) {
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	var otherID SessionID
	copy(otherID[:], []byte("server02"))

	encode := func(t *testing.T, keyID uint8, local SessionID) []byte {
		t.Helper()
		packet, err := (ControlPacket{
			Opcode:       PControlSoftResetV1,
			KeyID:        keyID,
			LocalSession: local,
			MessageID:    0,
		}).Encode(nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		return packet
	}

	tests := []struct {
		name   string
		packet []byte
	}{
		{"malformed", []byte{opcodeKeyID(PControlSoftResetV1, 1)}},
		{"initial key id", encode(t, 0, serverID)},
		{"wrong session", encode(t, 1, otherID)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientIO, serverIO := newMemoryPacketPair()
			client, err := NewClient(&ClientConfig{}, clientIO)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.control.SetRemoteSessionID(serverID)
			go client.watchControl()

			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if err := serverIO.WritePacket(ctx, test.packet); err != nil {
				t.Fatal(err)
			}
			select {
			case <-client.mux.done:
				t.Fatal("invalid packet closed client")
			case <-ctx.Done():
			}
			client.control.mu.Lock()
			recvMessage := client.control.recvMessage
			ackPending := len(client.control.ackPending)
			client.control.mu.Unlock()
			if recvMessage != 0 || ackPending != 0 {
				t.Fatalf("invalid packet changed reliable state: recv=%d pending-acks=%d", recvMessage, ackPending)
			}
		})
	}
}

func TestTCPPacketIOFraming(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientIO := NewTCPPacketIO(client)
	serverIO := NewTCPPacketIO(server)
	payload := []byte{1, 2, 3, 4}

	errCh := make(chan error, 1)
	go func() {
		errCh <- clientIO.WritePacket(context.Background(), payload)
	}()

	got, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("unexpected payload: %v", got)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
