package openvpn

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/tls"
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

	errCh := make(chan error, 1)
	go func() {
		packet, err := serverControl.Read(ctx)
		if err != nil {
			errCh <- err
			return
		}
		if packet.Opcode != PControlHardResetClientV2 {
			errCh <- errors.New("unexpected reset opcode")
			return
		}
		raw, err := serverIO.ReadPacket(ctx)
		if err != nil {
			errCh <- err
			return
		}
		packet, _, _, err = DecodeControlPacket(nil, raw)
		if err != nil {
			errCh <- err
			return
		}
		if packet.Opcode != PControlHardResetClientV2 || packet.MessageID != 0 {
			errCh <- errors.New("unexpected retransmitted reset packet")
			return
		}
		_, err = serverControl.Send(ctx, PControlHardResetServerV2, nil)
		errCh <- err
	}()

	if err := client.waitServerReset(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if clientControl.PendingMessages() != 0 {
		t.Fatalf("expected client reset to be acked, pending=%d", clientControl.PendingMessages())
	}
}

func TestClientReportsFailedSoftReset(t *testing.T) {
	serverCert, caPEM := testRekeyServerCertificate(t)
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
			config.CA = caPEM

			clientIO, serverIO := newMemoryPacketPair()
			client, err := NewClient(&config, clientIO)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var serverID SessionID
			copy(serverID[:], []byte("server01"))
			client.control.SetRemoteSessionID(serverID)
			serverControl := NewControlChannel(serverIO, serverCrypt, serverID)
			serverControl.SetRemoteSessionID(client.control.LocalSessionID())

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			startTestTLSControlWatcher(t, ctx, client, serverControl, serverCert)
			client.config.CA = nil
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
			ackCtx, ackCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			_, err = serverControl.Read(ackCtx)
			ackCancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline after consuming client ack, got %v", err)
			}
			if serverControl.PendingMessages() != 0 {
				t.Fatalf("expected client to ack ordinary control message: %d", serverControl.PendingMessages())
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
			// The empty test config has no CA, so the fresh TLS epoch cannot
			// be configured and the client should surface the rekey failure.
			select {
			case <-client.mux.done:
			case <-ctx.Done():
				t.Fatal("client did not close after soft reset renegotiation failure")
			}
			if client.control.recvMessage != 1 {
				t.Fatalf("new epoch receive sequence = %d; want 1", client.control.recvMessage)
			}
			if client.control.PendingMessages() != 1 {
				t.Fatalf("expected unacknowledged soft reset response, pending=%d", client.control.PendingMessages())
			}
			if client.Err() == nil || !strings.Contains(client.Err().Error(), "parse openvpn ca certificate") {
				t.Fatalf("unexpected client error: %v", client.Err())
			}
		})
	}
}

func TestClientControlWatcherIgnoresInvalidPackets(t *testing.T) {
	serverCert, caPEM := testRekeyServerCertificate(t)
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
			client, err := NewClient(&ClientConfig{CA: caPEM}, clientIO)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.control.SetRemoteSessionID(serverID)
			serverControl := NewControlChannel(serverIO, nil, serverID)
			serverControl.SetRemoteSessionID(client.control.LocalSessionID())

			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			startTestTLSControlWatcher(t, ctx, client, serverControl, serverCert)
			client.control.mu.Lock()
			initialRecvMessage := client.control.recvMessage
			initialAckPending := len(client.control.ackPending)
			client.control.mu.Unlock()
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
			if recvMessage != initialRecvMessage || ackPending != initialAckPending {
				t.Fatalf(
					"invalid packet changed reliable state: recv=%d want=%d pending-acks=%d want=%d",
					recvMessage,
					initialRecvMessage,
					ackPending,
					initialAckPending,
				)
			}
		})
	}
}

func startTestTLSControlWatcher(
	t *testing.T,
	ctx context.Context,
	client *Client,
	serverControl *ControlChannel,
	serverCert tls.Certificate,
) {
	t.Helper()
	serverTLS := tls.Server(NewControlConn(serverControl), &tls.Config{
		Certificates:           []tls.Certificate{serverCert},
		SessionTicketsDisabled: true,
	})
	if deadline, ok := ctx.Deadline(); ok {
		_ = serverTLS.SetDeadline(deadline)
	}
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- serverTLS.HandshakeContext(ctx)
	}()

	tlsConfig, err := client.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := tls.Client(NewControlConn(client.control), tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = clientTLS.SetDeadline(deadline)
	}
	if err := clientTLS.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	_ = clientTLS.SetDeadline(time.Time{})
	_ = serverTLS.SetDeadline(time.Time{})
	if !client.setTLSConn(clientTLS) {
		t.Fatal("failed to publish test TLS connection")
	}
	go client.watchControl()
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
