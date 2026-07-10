//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/types/key"
)

func TestTailscaleHostForwardOptionDecode(t *testing.T) {
	var option TailscaleOption
	err := structure.NewDecoder(structure.Option{
		TagName:          "proxy",
		WeaklyTypedInput: true,
		KeyReplacer:      structure.DefaultKeyReplacer,
	}).Decode(map[string]any{
		"name":      "test",
		"magic-dns": true,
		"host-forward": map[string]any{
			"enabled": true,
			"target":  "127.0.0.2",
			"tcp":     false,
			"udp":     true,
		},
	}, &option)
	if err != nil {
		t.Fatal(err)
	}
	if !option.MagicDNS {
		t.Fatal("magic-dns was not decoded")
	}
	if !option.HostForward.Enabled || option.HostForward.Target != "127.0.0.2" {
		t.Fatalf("decoded host-forward: %+v", option.HostForward)
	}
	if option.HostForward.TCP == nil || *option.HostForward.TCP {
		t.Fatalf("decoded tcp: %v", option.HostForward.TCP)
	}
	if option.HostForward.UDP == nil || !*option.HostForward.UDP {
		t.Fatalf("decoded udp: %v", option.HostForward.UDP)
	}
}

func TestTailscaleStatusFromIPN(t *testing.T) {
	lastSeen := time.Date(2026, 7, 10, 4, 0, 0, 0, time.UTC)
	status := &ipnstate.Status{
		BackendState:   ipn.Running.String(),
		MagicDNSSuffix: "tailnet.test",
		TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		Self: &ipnstate.PeerStatus{
			HostName:     "mihomo-tailnet-staging",
			DNSName:      "mihomo-tailnet-staging.tailnet.test.",
			OS:           "linux",
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			{}: {
				HostName:     "newvbox",
				DNSName:      "newvbox.tailnet.test.",
				OS:           "linux",
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.90.103.91")},
				Online:       true,
				LastSeen:     lastSeen,
				TxBytes:      42,
				RxBytes:      24,
			},
		},
	}

	got := tailscaleStatusFromIPN("ts", status)
	if got.Proxy != "ts" || got.BackendState != ipn.Running.String() {
		t.Fatalf("status metadata: %+v", got)
	}
	if got.Self == nil || got.Self.Name != "mihomo-tailnet-staging" || !got.Self.Online {
		t.Fatalf("self status: %+v", got.Self)
	}
	if len(got.Peers) != 1 {
		t.Fatalf("peers length: %d", len(got.Peers))
	}
	peer := got.Peers[0]
	if peer.Name != "newvbox" || len(peer.TailscaleIPs) != 1 || peer.TailscaleIPs[0] != "100.90.103.91" {
		t.Fatalf("peer status: %+v", peer)
	}
	if text := got.Text(); !strings.Contains(text, "newvbox") || !strings.Contains(text, "100.90.103.91") {
		t.Fatalf("status text missing peer: %s", text)
	}
}

func TestTailscaleHostForwardOptions(t *testing.T) {
	localIP := netip.MustParseAddr("100.64.0.1")
	localIPs := func() (netip.Addr, netip.Addr) { return localIP, netip.Addr{} }

	forwarder, err := newTailscaleHostForwarder(context.Background(), "test", TailscaleHostForwardOption{Enabled: true}, localIPs)
	if err != nil {
		t.Fatal(err)
	}
	if !forwarder.tcp || !forwarder.udp {
		t.Fatalf("default protocols: tcp=%v udp=%v", forwarder.tcp, forwarder.udp)
	}
	if forwarder.target != tailscaleHostForwardDefaultTarget {
		t.Fatalf("default target: %s", forwarder.target)
	}

	if _, err := newTailscaleHostForwarder(context.Background(), "test", TailscaleHostForwardOption{
		Enabled: true,
		Target:  "192.0.2.1",
	}, localIPs); err == nil {
		t.Fatal("expected non-loopback target to fail")
	}

	disabled := false
	if _, err := newTailscaleHostForwarder(context.Background(), "test", TailscaleHostForwardOption{
		Enabled: true,
		TCP:     &disabled,
		UDP:     &disabled,
	}, localIPs); err == nil {
		t.Fatal("expected disabled TCP and UDP to fail")
	}
}

func TestTailscaleHostForwardDisabledKeepsLazyStartup(t *testing.T) {
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(oldHome) })

	outbound, err := NewTailscale(TailscaleOption{
		Name:     "lazy-test",
		StateDir: "tailscale",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbound.Close() })

	if outbound.serverStarted {
		t.Fatal("host-forward disabled started tsnet eagerly")
	}
}

func TestTailscaleHostForwardDestinationFilter(t *testing.T) {
	localV4 := netip.MustParseAddr("100.64.0.1")
	localV6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	forwarder, err := newTailscaleHostForwarder(context.Background(), "test", TailscaleHostForwardOption{Enabled: true}, func() (netip.Addr, netip.Addr) {
		return localV4, localV6
	})
	if err != nil {
		t.Fatal(err)
	}

	src := netip.MustParseAddrPort("100.64.0.2:12345")
	if _, intercept := forwarder.handleTCP(src, netip.AddrPortFrom(localV4, 22)); !intercept {
		t.Fatal("local IPv4 TCP flow was not intercepted")
	}
	if _, intercept := forwarder.handleUDP(src, netip.AddrPortFrom(localV6, 53)); !intercept {
		t.Fatal("local IPv6 UDP flow was not intercepted")
	}
	if handler, intercept := forwarder.handleTCP(src, netip.MustParseAddrPort("192.0.2.1:22")); intercept || handler != nil {
		t.Fatal("subnet-routed TCP flow was intercepted")
	}
	if handler, intercept := forwarder.handleUDP(src, netip.MustParseAddrPort("100.64.0.3:53")); intercept || handler != nil {
		t.Fatal("foreign-node UDP flow was intercepted")
	}
}

func TestTailscaleHostForwardDialFailureClosesClient(t *testing.T) {
	localIP := netip.MustParseAddr("100.64.0.1")
	forwarder, err := newTailscaleHostForwarder(context.Background(), "test", TailscaleHostForwardOption{Enabled: true}, func() (netip.Addr, netip.Addr) {
		return localIP, netip.Addr{}
	})
	if err != nil {
		t.Fatal(err)
	}
	forwarder.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	tcpHandler, intercept := forwarder.handleTCP(netip.MustParseAddrPort("100.64.0.2:12345"), netip.AddrPortFrom(localIP, 22))
	if !intercept || tcpHandler == nil {
		t.Fatal("TCP handler was not installed")
	}
	tcpClient, tcpAccepted := net.Pipe()
	t.Cleanup(func() { _ = tcpClient.Close() })
	tcpHandler(tcpAccepted)
	if _, err := tcpClient.Write([]byte("x")); err == nil {
		t.Fatal("TCP client was not closed after dial failure")
	}

	udpHandler, intercept := forwarder.handleUDP(netip.MustParseAddrPort("100.64.0.2:12345"), netip.AddrPortFrom(localIP, 53))
	if !intercept || udpHandler == nil {
		t.Fatal("UDP handler was not installed")
	}
	udpClient := newTestPacketConn()
	udpHandler(udpClient)
	select {
	case <-udpClient.closed:
	case <-time.After(time.Second):
		t.Fatal("UDP client was not closed after dial failure")
	}
}

func TestTailscaleHostForwardTCP(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	localIP := netip.MustParseAddr("100.64.0.1")
	forwarder, err := newTailscaleHostForwarder(context.Background(), "test", TailscaleHostForwardOption{Enabled: true}, func() (netip.Addr, netip.Addr) {
		return localIP, netip.Addr{}
	})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	handler, intercept := forwarder.handleTCP(netip.MustParseAddrPort("100.64.0.2:12345"), netip.AddrPortFrom(localIP, port))
	if !intercept || handler == nil {
		t.Fatal("local Tailscale TCP flow was not intercepted")
	}
	if handler, intercept := forwarder.handleTCP(netip.MustParseAddrPort("100.64.0.2:12345"), netip.AddrPortFrom(netip.MustParseAddr("100.64.0.3"), port)); intercept || handler != nil {
		t.Fatal("non-local Tailscale TCP flow was intercepted")
	}

	client, accepted := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go handler(accepted)
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("tailscale host-forward tcp")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("reply %q, want %q", reply, payload)
	}
}

func TestTailscaleHostForwardUDP(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	go func() {
		buffer := make([]byte, 64*1024)
		n, peer, err := backend.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		_, _ = backend.WriteToUDP(buffer[:n], peer)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	localIP := netip.MustParseAddr("100.64.0.1")
	forwarder, err := newTailscaleHostForwarder(ctx, "test", TailscaleHostForwardOption{Enabled: true}, func() (netip.Addr, netip.Addr) {
		return localIP, netip.Addr{}
	})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(backend.LocalAddr().(*net.UDPAddr).Port)
	handler, intercept := forwarder.handleUDP(netip.MustParseAddrPort("100.64.0.2:12345"), netip.AddrPortFrom(localIP, port))
	if !intercept || handler == nil {
		t.Fatal("local Tailscale UDP flow was not intercepted")
	}

	client, accepted := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go handler(testConnPacketConn{Conn: accepted})
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("tailscale host-forward udp")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("reply %q, want %q", reply, payload)
	}
}

func TestRelayTailscaleHostUDPDatagramBoundaries(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	go func() {
		buffer := make([]byte, 64*1024)
		for i := 0; i < 2; i++ {
			n, peer, err := backend.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			response := append([]byte("echo:"), buffer[:n]...)
			_, _ = backend.WriteToUDP(response, peer)
		}
	}()

	backendConn, err := net.Dial("udp4", backend.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backendConn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newTestPacketConn()
	done := make(chan error, 1)
	go func() {
		done <- relayTailscaleHostUDP(ctx, client, backendConn, time.Minute)
	}()

	client.queueRead([]byte("one"))
	client.queueRead([]byte("two-two"))
	if got := client.readWritten(t); string(got) != "echo:one" {
		t.Fatalf("first datagram = %q", got)
	}
	if got := client.readWritten(t); string(got) != "echo:two-two" {
		t.Fatalf("second datagram = %q", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP relay did not stop after context cancellation")
	}
}

func TestRelayTailscaleHostUDPIdleCleanup(t *testing.T) {
	client, accepted := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	backend, backendPeer := net.Pipe()
	t.Cleanup(func() { _ = backendPeer.Close() })

	done := make(chan error, 1)
	go func() {
		done <- relayTailscaleHostUDP(context.Background(), testConnPacketConn{Conn: accepted}, backend, 20*time.Millisecond)
	}()

	select {
	case err := <-done:
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			t.Fatalf("relay error = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP relay did not stop after idle deadline")
	}
}

type testConnPacketConn struct {
	net.Conn
}

func (c testConnPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, err := c.Read(buffer)
	return n, c.RemoteAddr(), err
}

func (c testConnPacketConn) WriteTo(buffer []byte, _ net.Addr) (int, error) {
	return c.Write(buffer)
}

type testPacketConn struct {
	incoming chan []byte
	outgoing chan []byte
	closed   chan struct{}
	once     sync.Once
	local    net.Addr
	remote   net.Addr
}

func newTestPacketConn() *testPacketConn {
	return &testPacketConn{
		incoming: make(chan []byte, 8),
		outgoing: make(chan []byte, 8),
		closed:   make(chan struct{}),
		local:    &net.UDPAddr{IP: net.IPv4(100, 64, 0, 1), Port: 53},
		remote:   &net.UDPAddr{IP: net.IPv4(100, 64, 0, 2), Port: 12345},
	}
}

func (c *testPacketConn) queueRead(packet []byte) {
	packet = append([]byte(nil), packet...)
	select {
	case c.incoming <- packet:
	case <-c.closed:
	}
}

func (c *testPacketConn) readWritten(t *testing.T) []byte {
	t.Helper()
	select {
	case packet := <-c.outgoing:
		return packet
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for written packet")
		return nil
	}
}

func (c *testPacketConn) Read(buffer []byte) (int, error) {
	n, _, err := c.ReadFrom(buffer)
	return n, err
}

func (c *testPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.incoming:
		return copy(buffer, packet), c.remote, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *testPacketConn) Write(buffer []byte) (int, error) {
	packet := append([]byte(nil), buffer...)
	select {
	case c.outgoing <- packet:
		return len(buffer), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *testPacketConn) WriteTo(buffer []byte, _ net.Addr) (int, error) {
	return c.Write(buffer)
}

func (c *testPacketConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *testPacketConn) LocalAddr() net.Addr {
	return c.local
}

func (c *testPacketConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *testPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (c *testPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *testPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}
