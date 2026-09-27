package muxcool

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type testServerHandler struct {
	tcp func(context.Context, net.Conn, M.Metadata) error
	udp func(context.Context, N.PacketConn, M.Metadata) error
}

func TestServerPacketFlowWriteDeadlineFastPath(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	flow := newServerPacketFlow(
		nil, xudpFlowKey{}, ctx, cancel, testServerHandler{}, M.Socksaddr{},
		M.Socksaddr{Fqdn: "deadline.example", Port: 53}, false,
	)
	packet := buf.NewSize(1)
	defer packet.Release()
	_, _ = packet.Write([]byte{1})

	if err := flow.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := flow.WritePacket(packet, flow.destination); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired write = %v, want deadline exceeded", err)
	}
	if err := flow.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := flow.WritePacket(packet, flow.destination); err != nil {
		t.Fatalf("reset write = %v", err)
	}

	flow.closeWithError(io.EOF)
	if err := flow.WritePacket(packet, flow.destination); !errors.Is(err, io.EOF) {
		t.Fatalf("closed write = %v, want EOF", err)
	}
}

type manualServerTimer struct {
	stopped  atomic.Bool
	callback func()
}

type blockingErrorConn struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingErrorConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *blockingErrorConn) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return 0, io.ErrClosedPipe
}
func (c *blockingErrorConn) Close() error                     { return nil }
func (c *blockingErrorConn) LocalAddr() net.Addr              { return muxAddr("local") }
func (c *blockingErrorConn) RemoteAddr() net.Addr             { return muxAddr("remote") }
func (c *blockingErrorConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingErrorConn) SetWriteDeadline(time.Time) error { return nil }

func (t *manualServerTimer) Stop() bool {
	return !t.stopped.Swap(true)
}

func (t *manualServerTimer) Fire() {
	t.callback()
}

func (h testServerHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	return h.tcp(ctx, conn, metadata)
}

func (h testServerHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return h.udp(ctx, conn, metadata)
}

func testCarrierMetadata() M.Metadata {
	return M.Metadata{Source: M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.10"), Port: 32000}}
}

func serveTestCarrier(t *testing.T, runtime *ServerRuntime, handler ServerHandler) net.Conn {
	return serveTestCarrierContext(t, context.Background(), runtime, handler)
}

func serveTestCarrierContext(t *testing.T, ctx context.Context, runtime *ServerRuntime, handler ServerHandler) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- runtime.Serve(ctx, server, testCarrierMetadata(), handler)
	}()
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve did not stop")
		}
	})
	return client
}

func writeTestFrame(t *testing.T, conn net.Conn, frame Frame) {
	t.Helper()
	raw, err := EncodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFull(conn, raw); err != nil {
		t.Fatal(err)
	}
}

func readTestFrame(t *testing.T, conn net.Conn) Frame {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := DecodeFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestServerRuntimeMultiplexesTCP(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })

	handler := testServerHandler{
		tcp: func(_ context.Context, conn net.Conn, metadata M.Metadata) error {
			if metadata.Destination.Fqdn != "echo.example" || metadata.Destination.Port != 443 {
				return errors.New("unexpected destination")
			}
			payload := make([]byte, 32)
			n, err := conn.Read(payload)
			if err != nil {
				return err
			}
			_, err = conn.Write(payload[:n])
			return err
		},
		udp: func(context.Context, N.PacketConn, M.Metadata) error { return errors.New("unexpected UDP") },
	}
	carrier := serveTestCarrier(t, runtime, handler)

	writeTestFrame(t, carrier, Frame{
		SessionID: 7, Status: StatusNew, Option: OptionData, Network: NetworkTCP,
		Destination: "echo.example", Port: 443, Payload: []byte("hello"),
	})
	response := readTestFrame(t, carrier)
	if response.SessionID != 7 || response.Status != StatusKeep || string(response.Payload) != "hello" {
		t.Fatalf("response = %+v", response)
	}
}

func TestServerRuntimeRejectsDuplicateSessionIDBeforeDispatch(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })
	var calls atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	handler := testServerHandler{
		tcp: func(_ context.Context, conn net.Conn, _ M.Metadata) error {
			calls.Add(1)
			started <- struct{}{}
			<-release
			return conn.Close()
		},
		udp: func(context.Context, N.PacketConn, M.Metadata) error { return errors.New("unexpected UDP") },
	}
	carrier := serveTestCarrier(t, runtime, handler)
	frame := Frame{SessionID: 11, Status: StatusNew, Network: NetworkTCP, Destination: "one.example", Port: 80}
	writeTestFrame(t, carrier, frame)
	<-started
	writeTestFrame(t, carrier, frame)

	response := readTestFrame(t, carrier)
	if response.SessionID != 11 || response.Status != StatusEnd || response.Option&OptionError == 0 {
		t.Fatalf("duplicate response = %+v", response)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("dispatch calls = %d, want 1", got)
	}
	close(release)
}

func TestServerRuntimeEnforcesPerCarrierSessionLimit(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{MaxSessionsPerCarrier: 1, XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })
	var calls atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	handler := testServerHandler{
		tcp: func(_ context.Context, conn net.Conn, _ M.Metadata) error {
			calls.Add(1)
			started <- struct{}{}
			<-release
			return conn.Close()
		},
		udp: func(context.Context, N.PacketConn, M.Metadata) error { return errors.New("unexpected UDP") },
	}
	carrier := serveTestCarrier(t, runtime, handler)
	writeTestFrame(t, carrier, Frame{SessionID: 1, Status: StatusNew, Network: NetworkTCP, Destination: "one.example", Port: 80})
	<-started
	writeTestFrame(t, carrier, Frame{SessionID: 2, Status: StatusNew, Network: NetworkTCP, Destination: "two.example", Port: 80})
	response := readTestFrame(t, carrier)
	if response.SessionID != 2 || response.Status != StatusEnd || response.Option&OptionError == 0 {
		t.Fatalf("limit response = %+v", response)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("dispatch calls = %d, want 1", got)
	}
	close(release)
}

func TestServerRuntimePreservesUDPPacketsAndTargets(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })
	handler := testServerHandler{
		tcp: func(context.Context, net.Conn, M.Metadata) error { return errors.New("unexpected TCP") },
		udp: func(_ context.Context, conn N.PacketConn, metadata M.Metadata) error {
			if metadata.Destination.Fqdn != "dns.example" || metadata.Destination.Port != 53 {
				return errors.New("unexpected destination")
			}
			packet := buf.NewSize(MaxPayloadSize)
			defer packet.Release()
			destination, err := conn.ReadPacket(packet)
			if err != nil {
				return err
			}
			return conn.WritePacket(packet, destination)
		},
	}
	carrier := serveTestCarrier(t, runtime, handler)
	writeTestFrame(t, carrier, Frame{
		SessionID: 3, Status: StatusNew, Option: OptionData, Network: NetworkUDP,
		Destination: "dns.example", Port: 53, Payload: []byte("query"),
	})
	response := readTestFrame(t, carrier)
	if response.SessionID != 3 || response.Status != StatusKeep || response.Network != NetworkUDP ||
		response.Destination != "dns.example" || response.Port != 53 || string(response.Payload) != "query" {
		t.Fatalf("response = %+v", response)
	}
}

func TestServerRuntimeRebindsXUDPFlowAcrossCarriers(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })
	var calls atomic.Int32
	handler := testServerHandler{
		tcp: func(context.Context, net.Conn, M.Metadata) error { return errors.New("unexpected TCP") },
		udp: func(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
			calls.Add(1)
			for index := 0; index < 2; index++ {
				packet := buf.NewSize(MaxPayloadSize)
				destination, err := conn.ReadPacket(packet)
				if err != nil {
					packet.Release()
					return err
				}
				err = conn.WritePacket(packet, destination)
				packet.Release()
				if err != nil {
					return err
				}
			}
			return nil
		},
	}
	globalID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	firstCarrier := serveTestCarrier(t, runtime, handler)
	writeTestFrame(t, firstCarrier, Frame{
		SessionID: 1, Status: StatusNew, Option: OptionData, Network: NetworkUDP,
		Destination: "xudp.example", Port: 443, GlobalID: globalID, Payload: []byte("first"),
	})
	if response := readTestFrame(t, firstCarrier); string(response.Payload) != "first" {
		t.Fatalf("first response = %+v", response)
	}
	writeTestFrame(t, firstCarrier, Frame{SessionID: 1, Status: StatusEnd})

	secondCarrier := serveTestCarrier(t, runtime, handler)
	writeTestFrame(t, secondCarrier, Frame{
		SessionID: 9, Status: StatusNew, Option: OptionData, Network: NetworkUDP,
		Destination: "xudp.example", Port: 443, GlobalID: globalID, Payload: []byte("second"),
	})
	if response := readTestFrame(t, secondCarrier); response.SessionID != 9 || string(response.Payload) != "second" {
		t.Fatalf("second response = %+v", response)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("XUDP dispatch calls = %d, want 1", got)
	}
}

func TestServerRuntimeXUDPStaleAttachmentCannotDetachCurrent(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })
	var calls atomic.Int32
	handler := testServerHandler{
		tcp: func(context.Context, net.Conn, M.Metadata) error { return errors.New("unexpected TCP") },
		udp: func(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
			calls.Add(1)
			for index := 0; index < 3; index++ {
				packet := buf.NewSize(MaxPayloadSize)
				destination, err := conn.ReadPacket(packet)
				if err != nil {
					packet.Release()
					return err
				}
				err = conn.WritePacket(packet, destination)
				packet.Release()
				if err != nil {
					return err
				}
			}
			return nil
		},
	}
	globalID := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	first := serveTestCarrier(t, runtime, handler)
	writeTestFrame(t, first, Frame{
		SessionID: 1, Status: StatusNew, Option: OptionData, Network: NetworkUDP,
		Destination: "stable.example", Port: 53, GlobalID: globalID, Payload: []byte("one"),
	})
	if response := readTestFrame(t, first); string(response.Payload) != "one" {
		t.Fatalf("first response = %+v", response)
	}

	second := serveTestCarrier(t, runtime, handler)
	writeTestFrame(t, second, Frame{
		SessionID: 2, Status: StatusNew, Option: OptionData, Network: NetworkUDP,
		Destination: "stable.example", Port: 53, GlobalID: globalID, Payload: []byte("two"),
	})
	if retired := readTestFrame(t, first); retired.Status != StatusEnd || retired.SessionID != 1 {
		t.Fatalf("retired attachment frame = %+v", retired)
	}
	if response := readTestFrame(t, second); response.SessionID != 2 || string(response.Payload) != "two" {
		t.Fatalf("second response = %+v", response)
	}

	// A late frame from the retired carrier must not detach generation 2.
	writeTestFrame(t, first, Frame{SessionID: 1, Status: StatusEnd})
	writeTestFrame(t, second, Frame{
		SessionID: 2, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
		Destination: "stable.example", Port: 53, Payload: []byte("three"),
	})
	if response := readTestFrame(t, second); response.SessionID != 2 || string(response.Payload) != "three" {
		t.Fatalf("post-stale response = %+v", response)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("XUDP dispatch calls = %d, want 1", got)
	}
}

func TestServerRuntimeRejectsXUDPTargetMismatchWithoutReplacingFlow(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })
	var calls atomic.Int32
	release := make(chan struct{})
	handler := testServerHandler{
		tcp: func(context.Context, net.Conn, M.Metadata) error { return errors.New("unexpected TCP") },
		udp: func(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
			calls.Add(1)
			packet := buf.NewSize(MaxPayloadSize)
			defer packet.Release()
			_, err := conn.ReadPacket(packet)
			if err != nil {
				return err
			}
			<-release
			return nil
		},
	}
	globalID := [8]byte{4, 4, 4, 4, 4, 4, 4, 4}
	first := serveTestCarrier(t, runtime, handler)
	writeTestFrame(t, first, Frame{
		SessionID: 1, Status: StatusNew, Option: OptionData, Network: NetworkUDP,
		Destination: "first.example", Port: 53, GlobalID: globalID, Payload: []byte("one"),
	})
	writeTestFrame(t, first, Frame{SessionID: 1, Status: StatusEnd})

	second := serveTestCarrier(t, runtime, handler)
	writeTestFrame(t, second, Frame{
		SessionID: 2, Status: StatusNew, Option: OptionData, Network: NetworkUDP,
		Destination: "other.example", Port: 53, GlobalID: globalID, Payload: []byte("two"),
	})
	response := readTestFrame(t, second)
	if response.SessionID != 2 || response.Status != StatusEnd || response.Option&OptionError == 0 {
		t.Fatalf("target mismatch response = %+v", response)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("XUDP dispatch calls = %d, want 1", got)
	}
	close(release)
}

func TestServerRuntimeIsolatesXUDPFlowsByAuthenticatedUser(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })
	var calls atomic.Int32
	release := make(chan struct{})
	handler := testServerHandler{
		tcp: func(context.Context, net.Conn, M.Metadata) error { return errors.New("unexpected TCP") },
		udp: func(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
			calls.Add(1)
			packet := buf.NewSize(MaxPayloadSize)
			defer packet.Release()
			destination, err := conn.ReadPacket(packet)
			if err != nil {
				return err
			}
			if err := conn.WritePacket(packet, destination); err != nil {
				return err
			}
			<-release
			return nil
		},
	}
	globalID := [8]byte{9, 9, 9, 9, 9, 9, 9, 9}
	users := []string{"alice", "bob"}
	for index, user := range users {
		ctx := auth.ContextWithUser(context.Background(), user)
		carrier := serveTestCarrierContext(t, ctx, runtime, handler)
		writeTestFrame(t, carrier, Frame{
			SessionID: uint16(index + 1), Status: StatusNew, Option: OptionData, Network: NetworkUDP,
			Destination: "isolated.example", Port: 53, GlobalID: globalID, Payload: []byte(user),
		})
		if response := readTestFrame(t, carrier); string(response.Payload) != user {
			t.Fatalf("%s response = %+v", user, response)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("XUDP dispatch calls = %d, want 2", got)
	}
	close(release)
}

func TestServerRuntimeIgnoresStaleXUDPExpiryAfterRebind(t *testing.T) {
	timers := make(chan *manualServerTimer, 1)
	runtime := NewServerRuntime(ServerOptions{
		XUDPIdleTimeout: time.Minute,
		AfterFunc: func(_ time.Duration, callback func()) ServerTimer {
			timer := &manualServerTimer{callback: callback}
			timers <- timer
			return timer
		},
	})
	t.Cleanup(func() { _ = runtime.Close() })
	var calls atomic.Int32
	handler := testServerHandler{
		tcp: func(context.Context, net.Conn, M.Metadata) error { return errors.New("unexpected TCP") },
		udp: func(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
			calls.Add(1)
			for index := 0; index < 3; index++ {
				packet := buf.NewSize(MaxPayloadSize)
				destination, err := conn.ReadPacket(packet)
				if err != nil {
					packet.Release()
					return err
				}
				err = conn.WritePacket(packet, destination)
				packet.Release()
				if err != nil {
					return err
				}
			}
			return nil
		},
	}
	globalID := [8]byte{3, 1, 4, 1, 5, 9, 2, 6}
	first := serveTestCarrier(t, runtime, handler)
	writeTestFrame(t, first, Frame{
		SessionID: 1, Status: StatusNew, Option: OptionData, Network: NetworkUDP,
		Destination: "expiry.example", Port: 53, GlobalID: globalID, Payload: []byte("one"),
	})
	if response := readTestFrame(t, first); string(response.Payload) != "one" {
		t.Fatalf("first response = %+v", response)
	}
	writeTestFrame(t, first, Frame{SessionID: 1, Status: StatusEnd})
	staleTimer := <-timers

	second := serveTestCarrier(t, runtime, handler)
	writeTestFrame(t, second, Frame{
		SessionID: 2, Status: StatusNew, Option: OptionData, Network: NetworkUDP,
		Destination: "expiry.example", Port: 53, GlobalID: globalID, Payload: []byte("two"),
	})
	if response := readTestFrame(t, second); string(response.Payload) != "two" {
		t.Fatalf("second response = %+v", response)
	}

	// Simulate a callback that had already raced with Stop().
	staleTimer.Fire()
	writeTestFrame(t, second, Frame{
		SessionID: 2, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
		Destination: "expiry.example", Port: 53, Payload: []byte("three"),
	})
	if response := readTestFrame(t, second); string(response.Payload) != "three" {
		t.Fatalf("post-expiry response = %+v", response)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("XUDP dispatch calls = %d, want 1", got)
	}
}

func TestServerXUDPStaleWriteFailureDoesNotCloseCurrentGeneration(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{})
	ctx, cancel := context.WithCancelCause(context.Background())
	flow := newServerPacketFlow(
		runtime,
		xudpFlowKey{principal: "user:test", globalID: [8]byte{1}},
		ctx,
		cancel,
		testServerHandler{},
		testCarrierMetadata().Source,
		M.Socksaddr{Fqdn: "write.example", Port: 53},
		true,
	)
	oldConn := &blockingErrorConn{started: make(chan struct{}), release: make(chan struct{})}
	oldCarrier := newServerCarrier(runtime, context.Background(), oldConn, testCarrierMetadata(), testServerHandler{})
	oldAttachment := &serverPacketAttachment{flow: flow, carrier: oldCarrier, id: 1, generation: 1}
	flow.current = oldAttachment
	flow.currentFast.Store(oldAttachment)
	flow.generation = 1

	packet := buf.NewSize(MaxPayloadSize)
	if _, err := packet.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	result := make(chan error, 1)
	go func() {
		result <- flow.WritePacket(packet, M.Socksaddr{Fqdn: "write.example", Port: 53})
	}()
	<-oldConn.started

	newClient, newServer := net.Pipe()
	defer newClient.Close()
	defer newServer.Close()
	newCarrier := newServerCarrier(runtime, context.Background(), newServer, testCarrierMetadata(), testServerHandler{})
	newAttachment := &serverPacketAttachment{flow: flow, carrier: newCarrier, id: 2, generation: 2}
	flow.mu.Lock()
	flow.current = newAttachment
	flow.currentFast.Store(newAttachment)
	flow.generation = 2
	flow.mu.Unlock()
	close(oldConn.release)

	if err := <-result; err != nil {
		t.Fatalf("stale write error = %v, want suppression", err)
	}
	flow.mu.Lock()
	current := flow.current
	flow.mu.Unlock()
	if current != newAttachment {
		t.Fatal("stale write changed current attachment")
	}
}

func TestServerRuntimeCloseDrainsCarriers(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	client, server := net.Pipe()
	done := make(chan error, 1)
	handler := testServerHandler{
		tcp: func(context.Context, net.Conn, M.Metadata) error { return nil },
		udp: func(context.Context, N.PacketConn, M.Metadata) error { return nil },
	}
	go func() { done <- runtime.Serve(context.Background(), server, testCarrierMetadata(), handler) }()

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("carrier did not drain")
	}
	_ = client.Close()
	if err := runtime.Serve(context.Background(), client, testCarrierMetadata(), handler); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve after Close = %v, want ErrServerClosed", err)
	}
}
