//go:build with_gvisor && !no_tailscale

package outbound

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

type testProxyAddress struct{ raw net.Addr }

func (a testProxyAddress) Network() string   { return "proxy-session" }
func (a testProxyAddress) String() string    { return "opaque-session-id" }
func (a testProxyAddress) RawAddr() net.Addr { return a.raw }

type testProxyPacketConn struct{ net.PacketConn }

func (c testProxyPacketConn) LocalAddr() net.Addr { return testProxyAddress{c.PacketConn.LocalAddr()} }
func (c testProxyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	return n, testProxyAddress{addr}, err
}

type testProxyPacketDialer struct{ hint netip.AddrPort }

func (d *testProxyPacketDialer) ListenPacket(_ context.Context, network, address string, hint netip.AddrPort) (net.PacketConn, error) {
	d.hint = hint
	if !hint.IsValid() {
		return nil, errors.New("can't resolve ip: couldn't find ip")
	}
	pc, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return testProxyPacketConn{pc}, nil
}

func TestTailscaleProxyPacketMultipleDestinations(t *testing.T) {
	d := new(testProxyPacketDialer)
	if pc, err := d.ListenPacket(context.Background(), "udp4", "127.0.0.1:0", netip.AddrPort{}); err == nil {
		pc.Close()
		t.Fatal("fixture did not reproduce the original invalid-address failure")
	}
	pc, err := listenTailscaleProxyPacket(context.Background(), d, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if !d.hint.Addr().Is4() || !d.hint.Addr().IsUnspecified() || d.hint.Port() != 0 {
		t.Fatalf("invalid association hint: %v", d.hint)
	}
	if addr, ok := pc.LocalAddr().(*net.UDPAddr); !ok || addr.Port == 0 {
		t.Fatalf("actual bound local address was lost: %v", pc.LocalAddr())
	}
	for _, message := range [][]byte{[]byte("first-peer"), []byte("second-peer")} {
		echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer echo.Close()
		go func() {
			b := make([]byte, 64)
			n, from, e := echo.ReadFrom(b)
			if e == nil {
				_, _ = echo.WriteTo(b[:n], from)
			}
		}()
		if err := pc.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := pc.WriteTo(message, echo.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 64)
		n, from, err := pc.ReadFrom(b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b[:n], message) {
			t.Fatalf("unexpected payload %q", b[:n])
		}
		if _, ok := from.(*net.UDPAddr); !ok {
			t.Fatalf("source address was not normalized: %T", from)
		}
		if from.String() != echo.LocalAddr().String() {
			t.Fatalf("destination/source changed: got %v, want %v", from, echo.LocalAddr())
		}
	}
}

func TestTailscaleProxyPacketIPv6(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	probe.Close()
	d := new(testProxyPacketDialer)
	pc, err := listenTailscaleProxyPacket(context.Background(), d, "udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if !d.hint.Addr().Is6() || !d.hint.Addr().IsUnspecified() {
		t.Fatalf("wrong IPv6 association hint: %v", d.hint)
	}
}

func TestTailscaleProxyPacketRejectsNonUDP(t *testing.T) {
	if _, err := listenTailscaleProxyPacket(context.Background(), new(testProxyPacketDialer), "tcp", ":0"); err == nil {
		t.Fatal("accepted a TCP listener")
	}
}
