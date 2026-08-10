package openvpn

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
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

type datagramReadResult struct {
	packet []byte
	err    error
}

type scriptedDatagramConn struct {
	reads    []datagramReadResult
	writes   [][]byte
	writeErr error
}

func (c *scriptedDatagramConn) Read(b []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, net.ErrClosed
	}
	result := c.reads[0]
	c.reads = c.reads[1:]
	return copy(b, result.packet), result.err
}

func (c *scriptedDatagramConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes = append(c.writes, cloneBytes(b))
	return len(b), nil
}

func (c *scriptedDatagramConn) Close() error                     { return nil }
func (c *scriptedDatagramConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *scriptedDatagramConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *scriptedDatagramConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedDatagramConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedDatagramConn) SetWriteDeadline(time.Time) error { return nil }

func TestDatagramPacketIORecoversFromAsynchronousReadError(t *testing.T) {
	for name, errno := range map[string]syscall.Errno{
		"connection-refused": syscall.ECONNREFUSED,
		"connection-reset":   syscall.ECONNRESET,
		"message-too-long":   syscall.EMSGSIZE,
	} {
		t.Run(name, func(t *testing.T) {
			conn := &scriptedDatagramConn{
				reads: []datagramReadResult{
					{err: &net.OpError{Op: "read", Net: "udp", Err: errno}},
					{packet: []byte("next OpenVPN packet")},
				},
			}
			packetIO := NewDatagramPacketIO(conn)

			packet, err := packetIO.ReadPacket(context.Background())
			if err != nil {
				t.Fatalf("read after asynchronous ICMP error: %v", err)
			}
			if got, want := string(packet), "next OpenVPN packet"; got != want {
				t.Fatalf("packet = %q; want %q", got, want)
			}
		})
	}
}

func TestDatagramPacketIOWriteErrorHandling(t *testing.T) {
	for name, test := range map[string]struct {
		err         syscall.Errno
		recoverable bool
	}{
		"connection-refused": {err: syscall.ECONNREFUSED, recoverable: true},
		"connection-reset":   {err: syscall.ECONNRESET, recoverable: true},
		"message-too-long":   {err: syscall.EMSGSIZE},
	} {
		t.Run(name, func(t *testing.T) {
			conn := &scriptedDatagramConn{
				writeErr: &net.OpError{Op: "write", Net: "udp", Err: test.err},
			}
			packetIO := NewDatagramPacketIO(conn)

			err := packetIO.WritePacket(context.Background(), []byte("OpenVPN packet"))
			if test.recoverable && err != nil {
				t.Fatalf("recoverable write error = %v", err)
			}
			if !test.recoverable && !errors.Is(err, test.err) {
				t.Fatalf("write error = %v; want %v", err, test.err)
			}
		})
	}
}

func TestDatagramPacketIOSurfacesNonICMPError(t *testing.T) {
	ioErr := errors.New("UDP socket: invalid argument")
	conn := &scriptedDatagramConn{
		writeErr: ioErr,
		reads:    []datagramReadResult{{err: ioErr}},
	}
	packetIO := NewDatagramPacketIO(conn)

	if _, err := packetIO.ReadPacket(context.Background()); !errors.Is(err, ioErr) {
		t.Fatalf("read error = %v; want %v", err, ioErr)
	}
	if err := packetIO.WritePacket(context.Background(), []byte("packet")); !errors.Is(err, ioErr) {
		t.Fatalf("write error = %v; want %v", err, ioErr)
	}
}

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

type recordingPacketIO struct {
	PacketIO
	mu     sync.Mutex
	writes [][]byte
}

func (r *recordingPacketIO) WritePacket(ctx context.Context, packet []byte) error {
	r.mu.Lock()
	r.writes = append(r.writes, cloneBytes(packet))
	r.mu.Unlock()
	return r.PacketIO.WritePacket(ctx, packet)
}

func (r *recordingPacketIO) packets() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.writes...)
}

func TestControlConnChunksTLSWrites(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())
	// OpenVPN 2.6 can attach up to RELIABLE_ACK_SIZE (8) acknowledgements.
	// Exercise the largest normal tls-crypt header, not only the empty-ACK case.
	client.mu.Lock()
	for id := uint32(1); id <= 8; id++ {
		client.ackPending = append(client.ackPending, id)
	}
	client.mu.Unlock()

	recorder := &recordingPacketIO{PacketIO: client.io}
	client.io = recorder
	clientConn := NewControlConn(client)
	serverConn := NewControlConn(server)
	payload := make([]byte, 4*1024+17)
	for i := range payload {
		payload[i] = byte(i)
	}

	errCh := make(chan error, 1)
	go func() {
		n, err := clientConn.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		errCh <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("reassembled TLS stream differs from the written payload")
	}

	packets := recorder.packets()
	if len(packets) < 2 {
		t.Fatalf("control packet count = %d; want multiple bounded packets", len(packets))
	}
	for i, packet := range packets {
		if len(packet) > maxControlPacketSize {
			t.Fatalf("control packet %d size = %d; want at most %d", i, len(packet), maxControlPacketSize)
		}
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
