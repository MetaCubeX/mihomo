package openvpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

func (m *memoryPacketIO) WritePacketAllowActiveStop(ctx context.Context, packet []byte) error {
	return m.WritePacket(ctx, packet)
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

type controlIOPacketAdapter struct {
	io     ControlIO
	ctx    context.Context
	cancel context.CancelFunc
}

func (a *controlIOPacketAdapter) ReadPacket() ([]byte, error) {
	return a.io.ReadPacket(a.ctx)
}

func (a *controlIOPacketAdapter) WritePacket(packet []byte) error {
	return a.io.WritePacket(context.Background(), packet)
}

func (a *controlIOPacketAdapter) Close() error {
	a.cancel()
	return a.io.Close()
}
func (a *controlIOPacketAdapter) LocalAddr() net.Addr  { return a.io.LocalAddr() }
func (a *controlIOPacketAdapter) RemoteAddr() net.Addr { return a.io.RemoteAddr() }

type initialPacketRecordingIO struct {
	ControlIO
	marked chan struct{}
	once   sync.Once
}

func (i *initialPacketRecordingIO) markInitialPacketReceived() {
	i.once.Do(func() { close(i.marked) })
}

func newTestClient(config *ClientConfig, packetIO any) (*Client, error) {
	switch io := packetIO.(type) {
	case PacketIO:
		return NewClient(config, io)
	case ControlIO:
		ctx, cancel := context.WithCancel(context.Background())
		client, err := NewClient(config, &controlIOPacketAdapter{io: io, ctx: ctx, cancel: cancel})
		if err != nil {
			cancel()
		}
		return client, err
	default:
		return nil, fmt.Errorf("unsupported test packet IO %T", packetIO)
	}
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
	client.SetRemoteSessionID(serverID)
	server.SetRemoteSessionID(clientID)
	client.clock = func() time.Time { return time.Unix(1714567890, 0) }
	server.clock = func() time.Time { return time.Unix(1714567891, 0) }
	startTestACKFlusher(t, client)
	startTestACKFlusher(t, server)
	return client, server
}

func startTestACKFlusher(t *testing.T, channel *ControlChannel) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			select {
			case <-channel.ackWake:
				for channel.PendingACKs() > 0 {
					if channel.SendAck(ctx) != nil {
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
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

func TestReliableMessageWindowWraparound(t *testing.T) {
	base := ^uint32(0) - 1
	if !recvWindowOK(base, 0, 0) {
		t.Fatal("wrapped message id inside receive window was rejected")
	}
	if recvWindowOK(base, uint32(reliableCapacity-2), 0) {
		t.Fatal("wrapped message id at receive window edge was accepted")
	}
	if reliableMessageBefore(0, base) {
		t.Fatal("wrapped next message classified as replay")
	}
	if !reliableMessageBefore(base-1, base) {
		t.Fatal("previous message not classified as replay")
	}
	c := &ControlChannel{recvPending: make(map[uint32]*ControlPacket), recvMessage: base}
	c.MarkReceived(^uint32(0))
	if c.recvMessage != 0 {
		t.Fatalf("MarkReceived did not wrap sequence: %d", c.recvMessage)
	}
}

// TestOutOfWindowPacketNotAcked verifies the review point 3: a control packet
// whose message ID breaks the receive window is neither buffered nor
// acknowledged, so the sender keeps it for retransmission instead of dropping
// it and leaving a permanent hole.
// TestBufferedDuplicateReAcked verifies a retransmitted, already-buffered
// in-window packet is ACKed again without re-insertion or delivery. Its first
// ACK may have been lost, so suppressing the second ACK keeps the sender's
// reliable slot occupied indefinitely.
func TestBufferedDuplicateReAcked(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())
	serverIO := server.io.(*memoryPacketIO)

	inner := &ControlPacket{
		Opcode:       PControlV1,
		KeyID:        0,
		LocalSession: server.LocalSessionID(),
		MessageID:    1, // client expects 0: valid out-of-order, buffered
		Payload:      []byte("buffer me"),
	}
	sendAndRead := func(outerPID uint32) *ControlPacket {
		raw, err := inner.Encode(server.crypt, outerPID, uint32(server.clock().Unix()))
		if err != nil {
			t.Fatal(err)
		}
		if err := server.io.WritePacket(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, _ = client.read(ctx, false) // remains waiting for message 0
		select {
		case ackRaw := <-serverIO.in:
			ack, _, _, err := DecodeControlPacket(server.crypt, ackRaw)
			if err != nil {
				t.Fatal(err)
			}
			return ack
		default:
			t.Fatal("buffered in-window duplicate was not re-ACKed")
		}
		return nil
	}

	first := sendAndRead(1)
	if len(first.AckIDs) == 0 || first.AckIDs[0] != 1 {
		t.Fatalf("first ACK missing message 1: %v", first.AckIDs)
	}
	if len(client.recvPending) != 1 {
		t.Fatalf("message 1 not buffered: %d", len(client.recvPending))
	}
	second := sendAndRead(2)
	if len(second.AckIDs) == 0 || second.AckIDs[0] != 1 {
		t.Fatalf("duplicate ACK missing message 1: %v", second.AckIDs)
	}
	if len(client.recvPending) != 1 {
		t.Fatalf("duplicate was re-inserted: %d", len(client.recvPending))
	}
}

func TestOutOfWindowPacketNotAcked(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())

	// client expects message 0; a packet with message 12 is at the window
	// edge (recvMessage+reliableCapacity) and must be rejected, not ACKed.
	client.recvMessage = 0
	pkt := &ControlPacket{
		Opcode:       PControlV1,
		KeyID:        0,
		LocalSession: server.LocalSessionID(),
		MessageID:    12,
		Payload:      []byte("hello"),
	}
	raw, err := pkt.Encode(server.crypt, 1, uint32(client.clock().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	server.io.WritePacket(context.Background(), raw)

	// read() consumes the out-of-window packet and (correctly) does not
	// deliver it; it keeps reading, so bound the read with a short timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = client.read(ctx, false)
	if err == nil {
		t.Fatal("expected timeout while waiting after rejected window packet")
	}
	// No ACK must have been sent: ackPending stays empty and nothing goes out.
	client.mu.Lock()
	acked := len(client.ackPending)
	client.mu.Unlock()
	if acked != 0 {
		t.Fatalf("out-of-window message was ACKed (ackPending=%d)", acked)
	}
	// The other direction (client's outbound) must not contain an ACK packet:
	// nothing may have been written toward the server.
	serverIO := server.io.(*memoryPacketIO)
	select {
	case p := <-serverIO.in:
		t.Fatalf("unexpected outbound packet after rejected window: %x", p)
	default:
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
	// Key-state soft resets do not reset the outer tls-auth/tls-crypt replay
	// window; it belongs to the whole TLS session.
	c.beginEpochLocked(1)
	if err := c.checkReplayLocked(1, 1001); err == nil {
		t.Fatal("key epoch reset accepted an already-seen wrapper packet id")
	}
}

func TestControlChannelResetAndAck(t *testing.T) {
	client, server := newTestChannels(t)
	server.SetRemoteSessionID(client.LocalSessionID())

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
		t.Fatalf("server test remote session changed unexpectedly")
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
	server.SetRemoteSessionID(clientID)

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
	serverControl.SetRemoteSessionID(clientID)
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
			client, err := newTestClient(&ClientConfig{}, clientIO)
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

func TestControlReadDropsMalformedPacket(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	client := NewControlChannel(clientIO, nil, clientID)
	client.SetRemoteSessionID(serverID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := serverIO.WritePacket(ctx, []byte{opcodeKeyID(PControlV1, 0)}); err != nil {
		t.Fatal(err)
	}
	valid, err := (ControlPacket{
		Opcode:       PControlV1,
		LocalSession: serverID,
		MessageID:    0,
		Payload:      []byte("valid"),
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverIO.WritePacket(ctx, valid); err != nil {
		t.Fatal(err)
	}
	packet, err := client.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(packet.Payload) != "valid" {
		t.Fatalf("unexpected payload after malformed datagram: %q", packet.Payload)
	}
}

func TestControlConnWriteFragmentsTLSCiphertext(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	channel := NewControlChannel(clientIO, nil, clientID)
	conn := NewControlConn(channel)
	payload := bytes.Repeat([]byte{0x5a}, 2*maxTLSControlPayload+17)
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("Write = %d, want %d", n, len(payload))
	}
	var got []byte
	for i := 0; i < 3; i++ {
		raw, err := serverIO.ReadPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 1250 {
			t.Fatalf("control datagram length = %d, want <= 1250", len(raw))
		}
		packet, _, _, err := DecodeControlPacket(nil, raw)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Opcode != PControlV1 {
			t.Fatalf("opcode = %s, want %s", packet.Opcode, PControlV1)
		}
		got = append(got, packet.Payload...)

	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled payload length = %d, want %d", len(got), len(payload))
	}
}

type recordingPacketIO struct {
	writes int
}

func (p *recordingPacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *recordingPacketIO) WritePacket(context.Context, []byte) error {
	p.writes++
	return nil
}

func (p *recordingPacketIO) WritePacketAllowActiveStop(ctx context.Context, packet []byte) error {
	return p.WritePacket(ctx, packet)
}

func (*recordingPacketIO) Close() error         { return nil }
func (*recordingPacketIO) LocalAddr() net.Addr  { return nil }
func (*recordingPacketIO) RemoteAddr() net.Addr { return nil }

func TestExpiredControlWriteDeadlineSkipsPacketIO(t *testing.T) {
	packetIO := &recordingPacketIO{}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	channel := NewControlChannel(packetIO, nil, clientID)
	channel.QueueAck(1)
	if err := channel.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := channel.SendAck(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline returned %v", err)
	}
	if packetIO.writes != 0 {
		t.Fatalf("expired deadline reached PacketIO %d times", packetIO.writes)
	}
}

func TestControlSendGateObservesContext(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	channel := NewControlChannel(clientIO, nil, clientID)
	channel.QueueAck(1)
	channel.sendGate <- struct{}{}
	defer func() { <-channel.sendGate }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := channel.SendAck(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued control send returned %v", err)
	}
}

func TestControlConnCloseCancelsQueuedPayloadWrite(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	channel := NewControlChannel(clientIO, nil, clientID)
	conn := NewControlConn(channel)
	channel.sendGate <- struct{}{}
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("queued payload"))
		errCh <- err
	}()
	deadline := time.Now().Add(time.Second)
	for channel.PendingMessages() == 0 {
		if time.Now().After(deadline) {
			<-channel.sendGate
			t.Fatal("payload was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	if err := conn.Close(); err != nil {
		<-channel.sendGate
		t.Fatal(err)
	}
	<-channel.sendGate
	if err := <-errCh; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("queued payload write returned %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := serverIO.ReadPacket(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("payload emitted after Close: %v", err)
	}
}

func TestSoftResetReceivedAtStampedOnAcceptance(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	client := NewControlChannel(clientIO, nil, clientID)
	client.SetRemoteSessionID(serverID)
	reset, err := (ControlPacket{
		Opcode:       PControlSoftResetV1,
		KeyID:        1,
		LocalSession: serverID,
		MessageID:    0,
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := serverIO.WritePacket(ctx, reset); err != nil {
		t.Fatal(err)
	}
	packet, err := client.waitForSoftReset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	if packet.receivedAt.Before(before) || packet.receivedAt.After(after) {
		t.Fatalf("soft reset receivedAt = %v, want within [%v, %v]", packet.receivedAt, before, after)
	}
}

func TestProtectedSoftResetReplayRejectedAfterKeyReuse(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	clientCrypt, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	serverCrypt, err := NewTLSCrypt(testStaticKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	client := NewControlChannel(clientIO, clientCrypt, clientID)
	client.SetRemoteSessionID(serverID)
	client.keyID = 7
	client.recReplay = replayState{seen: true, time: 2000, highID: 100}
	client.recReplay.slots[0] = time.Now().UnixNano()

	stale, err := (ControlPacket{
		Opcode:       PControlSoftResetV1,
		KeyID:        1,
		LocalSession: serverID,
		MessageID:    0,
	}).Encode(serverCrypt, 5, 1000)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := serverIO.WritePacket(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := client.waitForSoftReset(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stale wrapped soft reset was accepted: %v", err)
	}
}

func TestProtectedControlTimestampStableAcrossPackets(t *testing.T) {
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
	channel := NewControlChannel(clientIO, clientCrypt, clientID)
	now := time.Unix(1000, 0)
	channel.clock = func() time.Time { return now }
	if _, err := channel.Send(context.Background(), PControlV1, []byte("one")); err != nil {
		t.Fatal(err)
	}
	now = time.Unix(2000, 0)
	if _, err := channel.Send(context.Background(), PControlV1, []byte("two")); err != nil {
		t.Fatal(err)
	}
	var times [2]uint32
	for i := range times {
		raw, err := serverIO.ReadPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_, _, times[i], err = DecodeControlPacket(serverCrypt, raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	if times != [2]uint32{1000, 1000} {
		t.Fatalf("protected packet timestamps = %v, want stable session time", times)
	}
}

func TestControlReplayRejectsZeroAndExpiredGap(t *testing.T) {
	channel := &ControlChannel{}
	now := time.Unix(100, 0)
	channel.replayClock = func() time.Time { return now }
	if err := channel.checkReplayLocked(0, 50); err == nil {
		t.Fatal("packet id zero accepted")
	}
	if err := channel.checkReplayLocked(1, 50); err != nil {
		t.Fatal(err)
	}
	if err := channel.checkReplayLocked(3, 50); err != nil {
		t.Fatal(err)
	}
	now = now.Add(controlReplayTimeBacktrack + time.Second)
	if err := channel.checkReplayLocked(2, 50); err == nil {
		t.Fatal("aged replay-window gap accepted")
	}
}

func TestUnsetRemoteSessionIgnoresNonResetPacket(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID, attackerID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(attackerID[:], []byte("attacker"))
	copy(serverID[:], []byte("server01"))
	recordingIO := &initialPacketRecordingIO{ControlIO: clientIO, marked: make(chan struct{})}
	channel := NewControlChannel(recordingIO, nil, clientID)
	bogus, err := (ControlPacket{Opcode: PAckV1, LocalSession: attackerID}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	reset, err := (ControlPacket{
		Opcode:       PControlHardResetServerV2,
		LocalSession: serverID,
		MessageID:    0,
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverIO.WritePacket(context.Background(), bogus); err != nil {
		t.Fatal(err)
	}
	if err := serverIO.WritePacket(context.Background(), reset); err != nil {
		t.Fatal(err)
	}
	packet, err := channel.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if packet.Opcode != PControlHardResetServerV2 || channel.RemoteSessionID() != serverID {
		t.Fatalf("remote pinned by non-reset: opcode=%s remote=%x", packet.Opcode, channel.RemoteSessionID())
	}
	select {
	case <-recordingIO.marked:
	default:
		t.Fatal("accepted initial hard reset did not mark the transport established")
	}
}

func TestTCPPacketIOWaitsForCompleteFrame(t *testing.T) {
	for _, bodyPartial := range []bool{false, true} {
		name := "prefix"
		if bodyPartial {
			name = "body"
		}
		t.Run(name, func(t *testing.T) {
			clientNet, serverNet := net.Pipe()
			defer clientNet.Close()
			defer serverNet.Close()
			packetIO := NewTCPPacketIO(clientNet)
			payload := []byte("hello")
			first := []byte{0}
			rest := append([]byte{byte(len(payload))}, payload...)
			if bodyPartial {
				first = []byte{0, byte(len(payload)), payload[0], payload[1]}
				rest = payload[2:]
			}
			readDone := make(chan struct {
				packet []byte
				err    error
			}, 1)
			go func() {
				packet, err := packetIO.ReadPacket()
				readDone <- struct {
					packet []byte
					err    error
				}{packet: packet, err: err}
			}()
			writeDone := make(chan error, 1)
			go func() {
				_, err := serverNet.Write(first)
				writeDone <- err
			}()
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
			select {
			case result := <-readDone:
				t.Fatalf("partial frame returned packet=%q err=%v", result.packet, result.err)
			case <-time.After(20 * time.Millisecond):
			}
			go func() { _, _ = serverNet.Write(rest) }()
			select {
			case result := <-readDone:
				if result.err != nil {
					t.Fatal(result.err)
				}
				if !bytes.Equal(result.packet, payload) {
					t.Fatalf("completed frame = %q, want %q", result.packet, payload)
				}
			case <-time.After(time.Second):
				t.Fatal("complete frame was not returned")
			}
		})
	}
}

func TestPacketMuxWriteGateObservesContext(t *testing.T) {
	clientNet, serverNet := net.Pipe()
	defer serverNet.Close()
	wrapper := &writeSignalingConn{Conn: clientNet, entered: make(chan struct{})}
	mux := NewPacketMux(NewTCPPacketIO(wrapper))
	defer mux.Close()
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- mux.WriteDataPacket(context.Background(), []byte("blocked"))
	}()
	<-wrapper.entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := mux.WriteDataPacket(ctx, []byte("queued")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued write returned %v", err)
	}
	_ = clientNet.Close()
	if err := <-firstDone; err == nil {
		t.Fatal("blocked write unexpectedly succeeded")
	}
}

func TestControlRejectsACKForDifferentSession(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID, serverID, otherID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	copy(otherID[:], []byte("other001"))
	client := NewControlChannel(clientIO, nil, clientID)
	client.SetRemoteSessionID(serverID)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.Send(ctx, PControlV1, []byte("pending")); err != nil {
		t.Fatal(err)
	}
	// Drain the outbound packet; only the malformed ACK is returned to client.
	if _, err := serverIO.ReadPacket(ctx); err != nil {
		t.Fatal(err)
	}
	ack, err := (ControlPacket{
		Opcode:           PAckV1,
		LocalSession:     serverID,
		AckIDs:           []uint32{0},
		AckRemoteSession: otherID,
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverIO.WritePacket(ctx, ack); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wrong-session ACK was accepted: %v", err)
	}
	if client.PendingMessages() != 1 {
		t.Fatalf("wrong-session ACK cleared pending reliable message")
	}
}

type deadlineRacePacketIO struct {
	packet  []byte
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *deadlineRacePacketIO) ReadPacket(context.Context) ([]byte, error) {
	p.once.Do(func() { close(p.started) })
	<-p.release
	return append([]byte(nil), p.packet...), nil
}

func (p *deadlineRacePacketIO) WritePacket(context.Context, []byte) error { return nil }
func (p *deadlineRacePacketIO) WritePacketAllowActiveStop(context.Context, []byte) error {
	return nil
}
func (p *deadlineRacePacketIO) Close() error         { return nil }
func (p *deadlineRacePacketIO) LocalAddr() net.Addr  { return nil }
func (p *deadlineRacePacketIO) RemoteAddr() net.Addr { return nil }

func TestReadDeadlineRaceDoesNotDropPacket(t *testing.T) {
	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	raw, err := (ControlPacket{
		Opcode:       PControlV1,
		LocalSession: serverID,
		MessageID:    0,
		Payload:      []byte("kept"),
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	packetIO := &deadlineRacePacketIO{
		packet: raw, started: make(chan struct{}), release: make(chan struct{}),
	}
	channel := NewControlChannel(packetIO, nil, clientID)
	channel.SetRemoteSessionID(serverID)
	result := make(chan *ControlPacket, 1)
	errCh := make(chan error, 1)
	go func() {
		packet, err := channel.Read(context.Background())
		result <- packet
		errCh <- err
	}()
	<-packetIO.started
	if err := channel.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	close(packetIO.release)
	select {
	case packet := <-result:
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
		if string(packet.Payload) != "kept" {
			t.Fatalf("deadline race returned %q", packet.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("packet was dropped when deadline changed")
	}
}

type blockingWritePacketIO struct {
	entered chan struct{}
	once    sync.Once
}

func (p *blockingWritePacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *blockingWritePacketIO) WritePacket(ctx context.Context, _ []byte) error {
	p.once.Do(func() { close(p.entered) })
	<-ctx.Done()
	return ctx.Err()
}

func (p *blockingWritePacketIO) WritePacketAllowActiveStop(ctx context.Context, packet []byte) error {
	return p.WritePacket(ctx, packet)
}

func (p *blockingWritePacketIO) Close() error         { return nil }
func (p *blockingWritePacketIO) LocalAddr() net.Addr  { return nil }
func (p *blockingWritePacketIO) RemoteAddr() net.Addr { return nil }

type heldCanceledWritePacketIO struct {
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
}

func (p *heldCanceledWritePacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *heldCanceledWritePacketIO) WritePacket(ctx context.Context, _ []byte) error {
	close(p.entered)
	<-ctx.Done()
	close(p.canceled)
	<-p.release
	return ctx.Err()
}

func (p *heldCanceledWritePacketIO) WritePacketAllowActiveStop(ctx context.Context, packet []byte) error {
	return p.WritePacket(ctx, packet)
}

func (*heldCanceledWritePacketIO) Close() error         { return nil }
func (*heldCanceledWritePacketIO) LocalAddr() net.Addr  { return nil }
func (*heldCanceledWritePacketIO) RemoteAddr() net.Addr { return nil }

func TestControlConnWriteDeadlineInterruptsBlockedWrite(t *testing.T) {
	packetIO := &blockingWritePacketIO{entered: make(chan struct{})}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	conn := NewControlConn(NewControlChannel(packetIO, nil, clientID))
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("TLS record"))
		errCh <- err
	}()
	<-packetIO.entered
	if err := conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked write returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetWriteDeadline did not interrupt blocked write")
	}
}

func TestControlConnCloseInterruptsBlockedWrite(t *testing.T) {
	packetIO := &blockingWritePacketIO{entered: make(chan struct{})}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	conn := NewControlConn(NewControlChannel(packetIO, nil, clientID))
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("TLS record"))
		errCh <- err
	}()
	<-packetIO.entered
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked write returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt blocked write")
	}
}

func TestTCPControlConnDeadlineInterruptsSocketRead(t *testing.T) {
	clientNet, serverNet := net.Pipe()
	defer serverNet.Close()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	mux := NewPacketMux(NewTCPPacketIO(clientNet))
	go mux.Run()
	defer mux.Close()
	conn := NewControlConn(NewControlChannel(mux, nil, clientID))
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		errCh <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("blocked TCP read returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP socket read ignored updated deadline")
	}
}

func TestProtectedControlPacketIDExhaustion(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	crypt, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	channel := NewControlChannel(clientIO, crypt, clientID)
	channel.sendPacketID = ^uint32(0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := channel.Send(ctx, PControlV1, []byte("must not send")); err == nil {
		t.Fatal("protected control packet ID rollover succeeded")
	}
	if _, err := serverIO.ReadPacket(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("packet emitted after control packet ID exhaustion: %v", err)
	}
}
func TestControlWriteDeadlineExtensionIgnoresOldTimer(t *testing.T) {
	packetIO := &blockingWritePacketIO{entered: make(chan struct{})}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	channel := NewControlChannel(packetIO, nil, clientID)
	conn := NewControlConn(channel)
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("blocked"))
		errCh <- err
	}()
	<-packetIO.entered
	if err := conn.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	channel.mu.Lock()
	oldWriteGeneration := channel.writeGeneration
	oldDeadlineGeneration := channel.writeDeadlineGeneration
	oldCancel := channel.writeCancel
	channel.mu.Unlock()
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Invoke the superseded callback deterministically after the extension.
	channel.cancelWriteGeneration(oldWriteGeneration, oldDeadlineGeneration, oldCancel)
	select {
	case err := <-errCh:
		t.Fatalf("superseded deadline canceled write: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("cleanup close returned %v", err)
	}
}

func TestControlWriteKeepsCancellationCauseAfterDeadlineChange(t *testing.T) {
	packetIO := &heldCanceledWritePacketIO{
		entered:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	channel := NewControlChannel(packetIO, nil, clientID)
	errCh := make(chan error, 1)
	go func() {
		_, err := channel.Send(context.Background(), PControlV1, []byte("blocked"))
		errCh <- err
	}()
	<-packetIO.entered
	channel.mu.Lock()
	cancel := channel.writeCancel
	channel.mu.Unlock()
	cancel(context.DeadlineExceeded)
	<-packetIO.canceled
	if err := channel.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	close(packetIO.release)
	if err := <-errCh; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write lost its cancellation cause after deadline change: %v", err)
	}
}

type writeSignalingConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *writeSignalingConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(p)
}

func TestTCPControlConnInterruptsSocketWrite(t *testing.T) {
	for _, closeConn := range []bool{false, true} {
		name := "deadline"
		if closeConn {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			clientNet, serverNet := net.Pipe()
			defer serverNet.Close()
			wrapped := &writeSignalingConn{Conn: clientNet, entered: make(chan struct{})}
			var clientID SessionID
			copy(clientID[:], []byte("client01"))
			mux := NewPacketMux(NewTCPPacketIO(wrapped))
			go mux.Run()
			defer mux.Close()
			conn := NewControlConn(NewControlChannel(mux, nil, clientID))
			errCh := make(chan error, 1)
			go func() {
				_, err := conn.Write([]byte("blocked socket write"))
				errCh <- err
			}()
			<-wrapped.entered
			if closeConn {
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-errCh:
				if closeConn {
					if !errors.Is(err, net.ErrClosed) {
						t.Fatalf("closed socket write returned %v", err)
					}
				} else {
					var netErr net.Error
					if !errors.Is(err, context.DeadlineExceeded) &&
						(!errors.As(err, &netErr) || !netErr.Timeout()) {
						t.Fatalf("deadline socket write returned %v", err)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("socket write was not interrupted")
			}
		})
	}
}

type ackCloseRacePacketIO struct {
	entered chan struct{}
	release chan struct{}
	mu      sync.Mutex
	writes  int
}

func (p *ackCloseRacePacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *ackCloseRacePacketIO) WritePacket(context.Context, []byte) error {
	p.mu.Lock()
	p.writes++
	n := p.writes
	p.mu.Unlock()
	if n == 1 {
		close(p.entered)
		<-p.release
	}
	return nil
}

func (p *ackCloseRacePacketIO) WritePacketAllowActiveStop(ctx context.Context, packet []byte) error {
	return p.WritePacket(ctx, packet)
}

func (p *ackCloseRacePacketIO) Close() error         { return nil }
func (p *ackCloseRacePacketIO) LocalAddr() net.Addr  { return nil }
func (p *ackCloseRacePacketIO) RemoteAddr() net.Addr { return nil }

func TestControlConnCloseAfterACKPreventsPayloadWrite(t *testing.T) {
	packetIO := &ackCloseRacePacketIO{entered: make(chan struct{}), release: make(chan struct{})}
	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	channel := NewControlChannel(packetIO, nil, clientID)
	channel.SetRemoteSessionID(serverID)
	channel.QueueAck(7)
	conn := NewControlConn(channel)
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("must not send after close"))
		errCh <- err
	}()
	<-packetIO.entered
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	close(packetIO.release)
	if err := <-errCh; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close returned %v", err)
	}
	packetIO.mu.Lock()
	writes := packetIO.writes
	packetIO.mu.Unlock()
	if writes != 1 {
		t.Fatalf("TLS payload was written after Close: writes=%d", writes)
	}
}

func TestControlConnDeadlineInterruptsBlockedRead(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	conn := NewControlConn(NewControlChannel(clientIO, nil, clientID))
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		errCh <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked read returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetReadDeadline did not interrupt blocked read")
	}
}

func TestControlConnCloseInterruptsBlockedRead(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	conn := NewControlConn(NewControlChannel(clientIO, nil, clientID))
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		errCh <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked read returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt blocked read")
	}
}

func TestControlConnCloseResetDoesNotLeaveReadDeadline(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	channel := NewControlChannel(clientIO, nil, clientID)
	channel.SetRemoteSessionID(serverID)
	conn := NewControlConn(channel)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	conn.Reset()

	type readResult struct {
		payload string
		err     error
	}
	result := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		result <- readResult{payload: string(buf[:n]), err: err}
	}()
	select {
	case got := <-result:
		t.Fatalf("read after Reset returned before a packet arrived: payload=%q err=%v", got.payload, got.err)
	case <-time.After(20 * time.Millisecond):
	}

	raw, err := (ControlPacket{
		Opcode:       PControlV1,
		LocalSession: serverID,
		MessageID:    0,
		Payload:      []byte("after reset"),
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverIO.WritePacket(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.payload != "after reset" {
			t.Fatalf("read after Reset returned %q", got.payload)
		}
	case <-time.After(time.Second):
		t.Fatal("read after Reset did not receive the packet")
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
		errCh <- clientIO.WritePacket(payload)
	}()

	got, err := serverIO.ReadPacket()
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
