//go:build with_gvisor && !no_tailscale

package outbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/structure"
)

func TestTailscaleHostForwardConfig(t *testing.T) {
	disabled := false
	for _, tc := range []struct {
		name   string
		option *TailscaleHostForwardOption
		want   *tailscaleHostForward
	}{
		{"omitted", nil, nil},
		{"disabled", &TailscaleHostForwardOption{}, nil},
		{"defaults", &TailscaleHostForwardOption{Enabled: true}, &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), true, true}},
		{"tcp only", &TailscaleHostForwardOption{Enabled: true, UDP: &disabled}, &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), true, false}},
		{"udp only", &TailscaleHostForwardOption{Enabled: true, TCP: &disabled}, &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), false, true}},
		{"ipv6 target", &TailscaleHostForwardOption{Enabled: true, Target: "::1"}, &tailscaleHostForward{netip.MustParseAddr("::1"), true, true}},
		{"mapped target", &TailscaleHostForwardOption{Enabled: true, Target: "::ffff:127.0.0.1"}, &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildTailscaleHostForward(tc.option)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == nil {
				if got != nil {
					t.Fatalf("host forwarding = %v, want disabled", got)
				}
			} else if got == nil || *got != *tc.want {
				t.Fatalf("host forwarding = %v, want %v", got, tc.want)
			}
		})
	}
	for _, target := range []string{"localhost", "127.0.0.1:6767", "192.168.123.1", "100.104.118.62", "0.0.0.0", "::", "::1%lo", "not-an-ip"} {
		t.Run("invalid "+target, func(t *testing.T) {
			if _, err := NewTailscale(TailscaleOption{HostForward: &TailscaleHostForwardOption{Enabled: true, Target: target}}); err == nil {
				t.Fatalf("accepted invalid host-forward target %q", target)
			}
		})
	}
}

func TestTailscaleHostForwardDecode(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	var option TailscaleOption
	err := decoder.Decode(map[string]any{
		"name":         "tailscale-host-forward-decode",
		"host-forward": map[string]any{"enabled": true, "target": "::1", "tcp": false, "udp": true},
	}, &option)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := NewTailscale(option)
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	if ts.hostForward == nil || ts.hostForward.target.String() != "::1" || ts.hostForward.tcp || !ts.hostForward.udp {
		t.Fatalf("decoded host forwarding = %v", ts.hostForward)
	}
	if ts.serverStarted {
		t.Fatal("config construction must not start the node")
	}
}

func TestTailscaleHostForwardStartsWithoutAdvertisedRoutes(t *testing.T) {
	ts, err := NewTailscale(TailscaleOption{Name: "tailscale-host-forward-start", HostForward: &TailscaleHostForwardOption{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	// A file in place of the state directory makes Start fail before any network
	// activity. The backend notification proves host-only nodes start eagerly.
	ts.server.Dir = filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(ts.server.Dir, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ts.StartBackground()
	select {
	case <-ts.backendInitCh:
		if ts.backendInitErr == nil {
			t.Fatal("expected the state-directory error from starting the node")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("host forwarding without advertised routes did not start the node")
	}
}

func TestTailscaleHostForwardDestination(t *testing.T) {
	ip4 := netip.MustParseAddr("100.104.118.62")
	ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1234")
	for _, tc := range []struct {
		name, network, dst, target string
		host                       *tailscaleHostForward
		routes                     []netip.Prefix
		outboundUDP                bool
		local                      bool
	}{
		{"own ipv4 tcp", "tcp", "100.104.118.62:6767", "127.0.0.1:6767", &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), true, true}, nil, false, true},
		{"own ipv6 tcp", "tcp", "[fd7a:115c:a1e0::1234]:6767", "127.0.0.1:6767", &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), true, true}, nil, false, true},
		{"own udp independent of outbound", "udp", "100.104.118.62:53", "[::1]:53", &tailscaleHostForward{netip.MustParseAddr("::1"), true, true}, nil, false, true},
		{"peer is not local", "tcp", "100.104.118.63:6767", "", &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), true, true}, nil, true, false},
		{"disabled", "tcp", "100.104.118.62:6767", "", nil, nil, true, false},
		{"disabled with exit route", "tcp", "100.104.118.62:6767", "", nil, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, true, false},
		{"tcp disabled with exit route", "tcp", "100.104.118.62:6767", "", &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), false, true}, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, true, false},
		{"udp disabled", "udp", "100.104.118.62:53", "", &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), true, false}, nil, true, false},
		{"subnet tcp unchanged", "tcp", "192.168.123.1:80", "192.168.123.1:80", &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), true, true}, []netip.Prefix{netip.MustParsePrefix("192.168.123.0/24")}, true, false},
		{"subnet udp unchanged", "udp", "192.168.123.1:53", "192.168.123.1:53", nil, []netip.Prefix{netip.MustParsePrefix("192.168.123.0/24")}, true, false},
		{"subnet udp disabled", "udp", "192.168.123.1:53", "", &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), true, true}, []netip.Prefix{netip.MustParsePrefix("192.168.123.0/24")}, false, false},
		{"port zero", "tcp", "100.104.118.62:0", "", &tailscaleHostForward{netip.MustParseAddr("127.0.0.1"), true, true}, nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := &Tailscale{option: TailscaleOption{UDP: tc.outboundUDP}, hostForward: tc.host, advertisedRoutes: tc.routes}
			target, local, ok := ts.forwardDestination(tc.network, netip.MustParseAddrPort(tc.dst), ip4, ip6)
			if ok != (tc.target != "") || local != tc.local || (ok && target.String() != tc.target) {
				t.Fatalf("destination = (%s, %v, %v), want (%s, %v, %v)", target, local, ok, tc.target, tc.local, tc.target != "")
			}
		})
	}
}

func TestTailscaleHostForwardTCP(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			ln, err := net.Listen("tcp", address)
			if err != nil {
				if address == "[::1]:0" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer ln.Close()
			backendDone := make(chan struct{})
			go func() {
				defer close(backendDone)
				c, err := ln.Accept()
				if err == nil {
					defer c.Close()
					_, _ = io.Copy(c, c)
				}
			}()
			client, incoming := net.Pipe()
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// A node's infrastructure proxy and interface must not be used for localhost.
			ts := &Tailscale{Base: &Base{iface: "nonexistent-interface", dialer: &tailscaleTestDialer{}}, ctx: ctx}
			dst := netip.MustParseAddrPort(ln.Addr().String())
			done := make(chan struct{})
			go func() { ts.forwardTCP(incoming, dst, ts.inboundDialer(true)); close(done) }()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			payload := []byte("host service through the Tailnet TCP relay")
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(client, buf); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf, payload) {
				t.Fatalf("TCP reply = %q", buf)
			}
			cancel()
			for _, ch := range []<-chan struct{}{done, backendDone} {
				select {
				case <-ch:
				case <-time.After(3 * time.Second):
					t.Fatal("host TCP forwarding did not stop on cancellation")
				}
			}
		})
	}
}

func TestTailscaleHostForwardUDP(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			echo, err := net.ListenPacket("udp", address)
			if err != nil {
				if address == "[::1]:0" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				buf := make([]byte, 65535)
				for {
					n, src, err := echo.ReadFrom(buf)
					if err != nil {
						return
					}
					_, _ = echo.WriteTo(buf[:n], src)
				}
			}()
			incoming, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer incoming.Close()
			client, err := net.DialUDP("udp4", nil, incoming.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ts := &Tailscale{Base: &Base{iface: "nonexistent-interface", dialer: &tailscaleTestDialer{}}, ctx: ctx}
			dst := netip.MustParseAddrPort(echo.LocalAddr().String())
			done := make(chan struct{})
			go func() {
				ts.forwardUDP(tailscaleTestUDPFlow{incoming, client.LocalAddr().(*net.UDPAddr)}, dst, ts.inboundDialer(true))
				close(done)
			}()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			for _, payload := range [][]byte{[]byte("host UDP service"), {}, []byte("another datagram")} {
				if _, err := client.Write(payload); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 65535)
				n, err := client.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf[:n], payload) {
					t.Fatalf("UDP reply = %q, want %q", buf[:n], payload)
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("host UDP forwarding did not stop on cancellation")
			}
		})
	}
}
