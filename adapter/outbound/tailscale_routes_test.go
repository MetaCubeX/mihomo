//go:build with_gvisor && !no_tailscale

package outbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestTailscaleAdvertisedRouteHandlers(t *testing.T) {
	ts := &Tailscale{option: TailscaleOption{UDP: true}, advertisedRoutes: []netip.Prefix{
		netip.MustParsePrefix("192.168.123.0/24"), netip.MustParsePrefix("fd12:3456::/64"),
	}}
	for _, tc := range []struct {
		dst  string
		want bool
	}{
		{"192.168.123.1:80", true}, {"[fd12:3456::1]:53", true},
		{"192.168.124.1:80", false}, {"100.100.100.100:53", false},
		{"192.168.123.1:0", false}, {"127.0.0.1:80", false},
	} {
		dst := netip.MustParseAddrPort(tc.dst)
		tcp, intercept := ts.tcpHandlerForAdvertisedRoute(netip.AddrPort{}, dst)
		if intercept != tc.want || (tcp != nil) != tc.want {
			t.Fatalf("TCP %s: intercept=%v handler=%v", tc.dst, intercept, tcp != nil)
		}
		udp, intercept := ts.udpHandlerForAdvertisedRoute(netip.AddrPort{}, dst)
		if intercept != tc.want || (udp != nil) != tc.want {
			t.Fatalf("UDP %s: intercept=%v handler=%v", tc.dst, intercept, udp != nil)
		}
	}
	ts.option.UDP = false
	if h, ok := ts.udpHandlerForAdvertisedRoute(netip.AddrPort{}, netip.MustParseAddrPort("192.168.123.1:53")); h != nil || ok {
		t.Fatal("UDP disabled")
	}
	ts.advertisedRoutes = nil
	if ts.advertisesDestination(netip.MustParseAddrPort("192.168.123.1:80")) {
		t.Fatal("withdrawn route still allowed")
	}
	// Default routes must not expose host-scoped or multicast addresses.
	ts.advertisedRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	for _, addr := range []string{"127.0.0.1:80", "[::1]:80", "169.254.1.1:80", "[fe80::1]:80", "224.0.0.1:80"} {
		if ts.advertisesDestination(netip.MustParseAddrPort(addr)) {
			t.Fatalf("host-scoped target allowed: %s", addr)
		}
	}
}

type tailscaleTestDialer struct {
	conn   net.Conn
	target string
}

func (d *tailscaleTestDialer) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	d.target = addr
	return d.conn, nil
}
func (d *tailscaleTestDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	panic("unexpected ListenPacket")
}

func TestTailscaleForwardTCPAndCancel(t *testing.T) {
	client, incoming := net.Pipe()
	backend, echo := net.Pipe()
	defer client.Close()
	defer echo.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &tailscaleTestDialer{conn: backend}
	ts := &Tailscale{Base: &Base{dialer: d}, ctx: ctx}
	done := make(chan struct{})
	go func() { ts.forwardAdvertisedTCP(incoming, netip.MustParseAddrPort("192.168.123.1:80")); close(done) }()
	go func() { _, _ = io.Copy(echo, echo) }()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("forward through the configured system dialer")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("response %q", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("TCP relay did not stop on cancellation")
	}
	if d.target != "192.168.123.1:80" {
		t.Fatalf("dialed %s", d.target)
	}
}

type tailscaleTestUDPFlow struct {
	*net.UDPConn
	peer *net.UDPAddr
}

func (c tailscaleTestUDPFlow) Write(p []byte) (int, error) { return c.WriteToUDP(p, c.peer) }

func TestTailscaleRelayUDP(t *testing.T) {
	for _, mode := range []string{"cancel", "idle"} {
		t.Run(mode, func(t *testing.T) {
			listen := func() *net.UDPConn {
				c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				if err := c.SetWriteBuffer(128 * 1024); err != nil {
					t.Fatal(err)
				}
				return c
			}
			incoming, backend, echo, rogue := listen(), listen(), listen(), listen()
			client, err := net.DialUDP("udp4", nil, incoming.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.SetWriteBuffer(128 * 1024); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			idle := 5 * time.Second
			if mode == "idle" {
				idle = 250 * time.Millisecond
			}
			done := make(chan struct{})
			go func() {
				tailscaleRelayUDP(ctx, tailscaleTestUDPFlow{incoming, client.LocalAddr().(*net.UDPAddr)}, backend, echo.LocalAddr().(*net.UDPAddr).AddrPort(), idle)
				close(done)
			}()
			go func() {
				buf := make([]byte, 65535)
				for {
					n, addr, err := echo.ReadFromUDP(buf)
					if err != nil {
						return
					}
					_, _ = echo.WriteToUDP(buf[:n], addr)
				}
			}()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			// A packet from any other source must not be returned to the Tailnet client.
			_, _ = rogue.WriteToUDP([]byte("wrong source"), backend.LocalAddr().(*net.UDPAddr))
			for _, payload := range [][]byte{[]byte("DNS-sized packet"), {}, bytes.Repeat([]byte("a"), 60000), []byte("last packet")} {
				if _, err := client.Write(payload); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 65535)
				n, err := client.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf[:n], payload) {
					t.Fatalf("datagram mismatch: got %d, want %d", n, len(payload))
				}
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatalf("UDP relay did not stop: %s", mode)
			}
		})
	}
}
