package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/muxcool"
)

type fakeMuxCoolAdapter struct {
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

func newFakeMuxCoolAdapter() *fakeMuxCoolAdapter {
	return &fakeMuxCoolAdapter{
		Base:           NewBase(BaseOption{Name: "fake", Addr: "fake:0", Type: C.Direct, UDP: true}),
		carrierServers: make(chan net.Conn, 8),
	}
}

func (f *fakeMuxCoolAdapter) DialContext(_ context.Context, metadata *C.Metadata) (C.Conn, error) {
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

func (f *fakeMuxCoolAdapter) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	f.mu.Lock()
	f.packetCalls++
	err := f.packetErr
	f.mu.Unlock()
	return nil, err
}

func (f *fakeMuxCoolAdapter) Close() error {
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

func (f *fakeMuxCoolAdapter) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dialMetadata)
}

func (f *fakeMuxCoolAdapter) firstMetadata() C.Metadata {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dialMetadata[0]
}

func TestMuxCoolDialsSentinelAndPoolsTCPStreams(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true}, base)
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
		frame, err := muxcool.DecodeFrame(server)
		if err != nil {
			t.Fatalf("decode New: %v", err)
		}
		if frame.Status != muxcool.StatusNew || string(frame.Payload) != write.data {
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
	if carrierMetadata.NetWork != C.TCP || carrierMetadata.Host != muxCoolDestination || carrierMetadata.DstPort != muxCoolPort {
		t.Fatalf("carrier metadata = %+v", carrierMetadata)
	}
}

func TestMuxCoolDoesNotBypassFailedCarrier(t *testing.T) {
	dialErr := errors.New("sentinel unavailable")
	base := newFakeMuxCoolAdapter()
	base.dialErr = dialErr
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true}, base)
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
	if metadata := base.firstMetadata(); metadata.Host != muxCoolDestination {
		t.Fatalf("dialed host = %q", metadata.Host)
	}
}

func TestMuxCoolDialContextDelegatesUDPStreams(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	udpClient, udpPeer := net.Pipe()
	t.Cleanup(func() { _ = udpPeer.Close() })
	base.udpConn = NewConn(udpClient, base)
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	metadata := &C.Metadata{NetWork: C.UDP, Host: "udp.example", DstPort: 53}

	conn, err := wrapped.DialContext(context.Background(), metadata)
	if err != nil || conn != base.udpConn {
		t.Fatalf("UDP DialContext = (%v, %v)", conn, err)
	}
}

func TestMuxCoolPoolsUDPAndDerivesXUDPGlobalID(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	base.Base.udp = false
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Host:    "dns.example",
		DstPort: 53,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 4242,
	}

	packetConn, err := wrapped.ListenPacketContext(context.Background(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	server := <-base.carrierServers
	t.Cleanup(func() { _ = server.Close() })

	queryAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("8.8.8.8:53"))
	writeDone := make(chan error, 1)
	go func() {
		_, err := packetConn.WriteTo([]byte("query"), queryAddr)
		writeDone <- err
	}()
	frame, err := muxcool.DecodeFrame(server)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if frame.Status != muxcool.StatusNew || frame.Network != muxcool.NetworkUDP || frame.Destination != "dns.example" || frame.Port != 53 {
		t.Fatalf("UDP New = %+v", frame)
	}
	if want := utils.GlobalID(metadata.SourceAddress()); frame.GlobalID != want {
		t.Fatalf("GlobalID = %v, want %v", frame.GlobalID, want)
	}
	if string(frame.Payload) != "query" {
		t.Fatalf("payload = %q", frame.Payload)
	}

	response, err := muxcool.EncodeFrame(muxcool.Frame{
		SessionID: frame.SessionID, Status: muxcool.StatusKeep, Option: muxcool.OptionData,
		Network: muxcool.NetworkUDP, Destination: "8.8.4.4", Port: 53, Payload: []byte("answer"),
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = server.Write(response) }()
	buffer := make([]byte, 16)
	n, addr, err := packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "answer" || addr.String() != "8.8.4.4:53" {
		t.Fatalf("ReadFrom = (%q, %v)", buffer[:n], addr)
	}

	base.mu.Lock()
	packetCalls := base.packetCalls
	base.mu.Unlock()
	if packetCalls != 0 {
		t.Fatalf("base packet calls = %d, want 0", packetCalls)
	}
	if !wrapped.SupportUDP() || !wrapped.SupportUOT() || !wrapped.ProxyInfo().XUDP {
		t.Fatalf("capabilities = UDP %t UOT %t XUDP %t", wrapped.SupportUDP(), wrapped.SupportUOT(), wrapped.ProxyInfo().XUDP)
	}
}

func TestMuxCoolUsesNormalUDPWithoutSourceIdentity(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	packetConn, err := wrapped.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, Host: "dns.example", DstPort: 53})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	server := <-base.carrierServers
	t.Cleanup(func() { _ = server.Close() })

	go func() {
		_, _ = packetConn.WriteTo([]byte("query"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.1.1.1:53")))
	}()
	frame, err := muxcool.DecodeFrame(server)
	if err != nil {
		t.Fatal(err)
	}
	if frame.GlobalID != [8]byte{} {
		t.Fatalf("GlobalID = %v, want normal UDP", frame.GlobalID)
	}
}

func TestMuxCoolUsesDedicatedPoolWhenXUDPConcurrencyIsPositive(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{
		Enabled:         true,
		MaxConcurrency:  8,
		XUDPConcurrency: 4,
		XUDPProxyUDP443: "allow",
	}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	stream, err := wrapped.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "tcp.example", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	packetConn, err := wrapped.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, Host: "udp.example", DstPort: 53})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })

	if got := base.dialCount(); got != 2 {
		t.Fatalf("carrier dial count = %d, want separate TCP and XUDP carriers", got)
	}
	for i := 0; i < 2; i++ {
		server := <-base.carrierServers
		t.Cleanup(func() { _ = server.Close() })
	}
}

func TestMuxCoolSharesPoolWhenXUDPConcurrencyIsZero(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	stream, err := wrapped.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "tcp.example", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	packetConn, err := wrapped.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, Host: "udp.example", DstPort: 53})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	server := <-base.carrierServers
	t.Cleanup(func() { _ = server.Close() })

	if got := base.dialCount(); got != 1 {
		t.Fatalf("carrier dial count = %d, want shared TCP and XUDP carrier", got)
	}
}

func TestMuxCoolEnforcesDedicatedXUDPConcurrency(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true, XUDPConcurrency: 1}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	var packetConns []C.PacketConn
	for i := 0; i < 2; i++ {
		packetConn, err := wrapped.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, Host: "udp.example", DstPort: 53})
		if err != nil {
			t.Fatal(err)
		}
		packetConns = append(packetConns, packetConn)
	}
	t.Cleanup(func() {
		for _, packetConn := range packetConns {
			_ = packetConn.Close()
		}
	})

	if got := base.dialCount(); got != 2 {
		t.Fatalf("carrier dial count = %d, want 2 at XUDP concurrency 1", got)
	}
	for i := 0; i < 2; i++ {
		server := <-base.carrierServers
		t.Cleanup(func() { _ = server.Close() })
	}
}

func TestMuxCoolRejectsUDP443ByDefault(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	packetConn, err := wrapped.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, Host: "quic.example", DstPort: 443})
	if packetConn != nil || !errors.Is(err, ErrMuxCoolUDP443Rejected) {
		t.Fatalf("ListenPacketContext = (%v, %v), want UDP/443 rejection", packetConn, err)
	}
	if got := base.dialCount(); got != 0 {
		t.Fatalf("carrier dial count = %d, want 0", got)
	}
}

func TestMuxCoolAllowsUDP443(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true, XUDPProxyUDP443: "allow"}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	packetConn, err := wrapped.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, Host: "quic.example", DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	server := <-base.carrierServers
	t.Cleanup(func() { _ = server.Close() })

	if got := base.dialCount(); got != 1 {
		t.Fatalf("carrier dial count = %d, want 1", got)
	}
	base.mu.Lock()
	packetCalls := base.packetCalls
	base.mu.Unlock()
	if packetCalls != 0 {
		t.Fatalf("base packet calls = %d, want 0", packetCalls)
	}
}

func TestMuxCoolSkipsUDP443(t *testing.T) {
	skipErr := errors.New("base UDP called")
	base := newFakeMuxCoolAdapter()
	base.packetErr = skipErr
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true, XUDPProxyUDP443: "skip"}, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	packetConn, err := wrapped.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, Host: "quic.example", DstPort: 443})
	if packetConn != nil || !errors.Is(err, skipErr) {
		t.Fatalf("ListenPacketContext = (%v, %v), want base proxy result", packetConn, err)
	}
	if got := base.dialCount(); got != 0 {
		t.Fatalf("carrier dial count = %d, want 0", got)
	}
	base.mu.Lock()
	packetCalls := base.packetCalls
	base.mu.Unlock()
	if packetCalls != 1 {
		t.Fatalf("base packet calls = %d, want 1", packetCalls)
	}
}

func TestMuxCoolServerFirstNewFrame(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true}, base)
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
	frame, err := muxcool.DecodeFrame(server)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Status != muxcool.StatusNew || frame.Option&muxcool.OptionData != 0 || len(frame.Payload) != 0 {
		t.Fatalf("server-first frame = %+v", frame)
	}
}

func TestMuxCoolContextCancellationClosesOnlyLogicalSession(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true}, base)
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
	end, err := muxcool.DecodeFrame(server)
	if err != nil {
		t.Fatalf("decode cancelled End: %v", err)
	}
	if end.SessionID != 1 || end.Status != muxcool.StatusEnd {
		t.Fatalf("cancel frame = %+v", end)
	}
	if _, err := first.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read error = %v", err)
	}

	response, err := muxcool.EncodeFrame(muxcool.Frame{SessionID: 2, Status: muxcool.StatusKeep, Option: muxcool.OptionData, Payload: []byte("ok")})
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

func TestMuxCoolCloseClosesPoolBeforeBaseExactlyOnce(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true}, base)
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

func TestMuxCoolCloseClosesDedicatedXUDPPoolBeforeBase(t *testing.T) {
	base := newFakeMuxCoolAdapter()
	wrapped, err := NewMuxCool(MuxCoolOption{Enabled: true, XUDPConcurrency: 4}, base)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := wrapped.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "close.example", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	packetConn, err := wrapped.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, Host: "close.example", DstPort: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	for i := 0; i < 2; i++ {
		server := <-base.carrierServers
		defer server.Close()
	}

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
		t.Fatalf("base close calls = %d, want 1", closeCalls)
	}
	if len(events) != 3 || events[0] != "carrier" || events[1] != "carrier" || events[2] != "base" {
		t.Fatalf("close events = %v, want both carriers before base", events)
	}
}
