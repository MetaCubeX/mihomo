package outbound

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/xraymux"
)

type fakeXrayMuxAdapter struct {
	*Base
	mu             sync.Mutex
	dialMetadata   []C.Metadata
	carrierServers chan net.Conn
	dialErr        error
	udpConn        C.Conn
	packetErr      error
	packetCalls    int
	closeCalls     int
	events         []string
}

func newFakeXrayMuxAdapter() *fakeXrayMuxAdapter {
	return &fakeXrayMuxAdapter{
		Base:           NewBase(BaseOption{Name: "fake", Addr: "fake:0", Type: C.Direct, UDP: true}),
		carrierServers: make(chan net.Conn, 8),
	}
}

func (f *fakeXrayMuxAdapter) DialContext(_ context.Context, metadata *C.Metadata) (C.Conn, error) {
	f.mu.Lock()
	f.dialMetadata = append(f.dialMetadata, *metadata)
	err := f.dialErr
	udpConn := f.udpConn
	f.mu.Unlock()
	if metadata.NetWork == C.UDP && udpConn != nil {
		return udpConn, err
	}
	if err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	f.carrierServers <- server
	return NewConn(&closeEventConn{Conn: client, onClose: func() {
		f.mu.Lock()
		f.events = append(f.events, "carrier")
		f.mu.Unlock()
	}}, f), nil
}

func (f *fakeXrayMuxAdapter) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	f.mu.Lock()
	f.packetCalls++
	err := f.packetErr
	f.mu.Unlock()
	return nil, err
}

func (f *fakeXrayMuxAdapter) Close() error {
	f.mu.Lock()
	f.closeCalls++
	f.events = append(f.events, "base")
	f.mu.Unlock()
	return nil
}

type closeEventConn struct {
	net.Conn
	closeOnce sync.Once
	onClose   func()
}

func (c *closeEventConn) Close() error {
	c.closeOnce.Do(c.onClose)
	return c.Conn.Close()
}

func (f *fakeXrayMuxAdapter) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dialMetadata)
}

func (f *fakeXrayMuxAdapter) firstMetadata() C.Metadata {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dialMetadata[0]
}

func TestXrayMuxDialsSentinelAndPoolsTCPStreams(t *testing.T) {
	base := newFakeXrayMuxAdapter()
	wrapped, err := NewXrayMux(XrayMuxOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	first, err := wrapped.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "one.example", DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	second, err := wrapped.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "two.example", DstPort: 8443})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close(); _ = second.Close() })

	server := <-base.carrierServers
	t.Cleanup(func() { _ = server.Close() })
	writes := []struct {
		conn C.Conn
		data string
	}{
		{conn: first, data: "first"},
		{conn: second, data: "second"},
	}
	for _, write := range writes {
		done := make(chan error, 1)
		go func() { _, err := write.conn.Write([]byte(write.data)); done <- err }()
		frame, err := xraymux.DecodeFrame(server)
		if err != nil {
			t.Fatalf("decode New: %v", err)
		}
		if frame.Status != xraymux.StatusNew || string(frame.Payload) != write.data {
			t.Fatalf("New frame = %+v", frame)
		}
		if err := <-done; err != nil {
			t.Fatalf("logical write: %v", err)
		}
	}
	if got := base.dialCount(); got != 1 {
		t.Fatalf("base dial count = %d, want 1", got)
	}
	carrierMetadata := base.firstMetadata()
	if carrierMetadata.NetWork != C.TCP || carrierMetadata.Host != xrayMuxDestination || carrierMetadata.DstPort != xrayMuxPort {
		t.Fatalf("carrier metadata = %+v", carrierMetadata)
	}
}

func TestXrayMuxDoesNotBypassFailedCarrier(t *testing.T) {
	dialErr := errors.New("sentinel unavailable")
	base := newFakeXrayMuxAdapter()
	base.dialErr = dialErr
	wrapped, err := NewXrayMux(XrayMuxOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	conn, err := wrapped.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "target.example", DstPort: 443})
	if conn != nil || !errors.Is(err, dialErr) {
		t.Fatalf("DialContext = (%v, %v), want carrier error", conn, err)
	}
	if got := base.dialCount(); got != 1 {
		t.Fatalf("base dial count = %d, want no fallback", got)
	}
	if metadata := base.firstMetadata(); metadata.Host != xrayMuxDestination {
		t.Fatalf("dialed host = %q", metadata.Host)
	}
}

func TestXrayMuxDelegatesUDPUnchanged(t *testing.T) {
	base := newFakeXrayMuxAdapter()
	udpClient, udpPeer := net.Pipe()
	t.Cleanup(func() { _ = udpPeer.Close() })
	base.udpConn = NewConn(udpClient, base)
	packetErr := errors.New("packet delegate marker")
	base.packetErr = packetErr
	wrapped, err := NewXrayMux(XrayMuxOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	metadata := &C.Metadata{NetWork: C.UDP, Host: "udp.example", DstPort: 53}

	conn, err := wrapped.DialContext(context.Background(), metadata)
	if err != nil || conn != base.udpConn {
		t.Fatalf("UDP DialContext = (%v, %v)", conn, err)
	}
	packetConn, err := wrapped.ListenPacketContext(context.Background(), metadata)
	if packetConn != nil || !errors.Is(err, packetErr) {
		t.Fatalf("ListenPacketContext = (%v, %v)", packetConn, err)
	}
	base.mu.Lock()
	packetCalls := base.packetCalls
	base.mu.Unlock()
	if packetCalls != 1 {
		t.Fatalf("packet calls = %d", packetCalls)
	}
}

func TestXrayMuxServerFirstNewFrame(t *testing.T) {
	base := newFakeXrayMuxAdapter()
	wrapped, err := NewXrayMux(XrayMuxOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	conn, err := wrapped.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "smtp.example", DstPort: 25})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	server := <-base.carrierServers
	t.Cleanup(func() { _ = server.Close() })
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := xraymux.DecodeFrame(server)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Status != xraymux.StatusNew || frame.Option&xraymux.OptionData != 0 || len(frame.Payload) != 0 {
		t.Fatalf("server-first frame = %+v", frame)
	}
}

func TestXrayMuxContextCancellationClosesOnlyLogicalSession(t *testing.T) {
	base := newFakeXrayMuxAdapter()
	wrapped, err := NewXrayMux(XrayMuxOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	first, err := wrapped.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "cancel.example", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	second, err := wrapped.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "survivor.example", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close(); _ = second.Close() })
	server := <-base.carrierServers
	t.Cleanup(func() { _ = server.Close() })

	cancel()
	end, err := xraymux.DecodeFrame(server)
	if err != nil {
		t.Fatalf("decode cancelled End: %v", err)
	}
	if end.SessionID != 1 || end.Status != xraymux.StatusEnd {
		t.Fatalf("cancel frame = %+v", end)
	}
	if _, err := first.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read error = %v", err)
	}

	response, err := xraymux.EncodeFrame(xraymux.Frame{SessionID: 2, Status: xraymux.StatusKeep, Option: xraymux.OptionData, Payload: []byte("ok")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = server.Write(response) }()
	got := make([]byte, 2)
	if _, err := second.Read(got); err != nil {
		t.Fatalf("surviving session read: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("surviving response = %q", got)
	}
}

func TestXrayMuxCloseClosesPoolBeforeBaseExactlyOnce(t *testing.T) {
	base := newFakeXrayMuxAdapter()
	wrapped, err := NewXrayMux(XrayMuxOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := wrapped.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "close.example", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := <-base.carrierServers
	defer server.Close()

	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	base.mu.Lock()
	events := append([]string(nil), base.events...)
	closeCalls := base.closeCalls
	base.mu.Unlock()
	if closeCalls != 1 {
		t.Fatalf("base close calls = %d", closeCalls)
	}
	if len(events) < 2 || events[0] != "carrier" || events[len(events)-1] != "base" {
		t.Fatalf("close events = %v, want carrier before base", events)
	}
}
