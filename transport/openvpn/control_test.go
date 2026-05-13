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
