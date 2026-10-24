package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/loopback"
	C "github.com/metacubex/mihomo/constant"
)

type packetListenFunc func(context.Context, string, string, netip.AddrPort) (net.PacketConn, error)

func (f packetListenFunc) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	return f(ctx, network, address, remote)
}

func (packetListenFunc) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, C.ErrNotSupport
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

func udpMetadata(pc *net.UDPConn) *C.Metadata {
	return &C.Metadata{SrcIP: netip.MustParseAddr("127.0.0.1"), SrcPort: uint16(pc.LocalAddr().(*net.UDPAddr).Port), DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 1234}
}

func requireClosed(t *testing.T, pc net.PacketConn) {
	t.Helper()
	if err := pc.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("discarded socket is still open: %v", err)
	}
}

func TestDirectUDPPortCollision(t *testing.T) {
	conflict := listenUDP(t)
	metadata := udpMetadata(conflict)
	d := NewDirect()
	d.loopBack = &loopback.Detector{}
	var safe *net.UDPConn
	calls := 0
	dialer := packetListenFunc(func(_ context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
		calls++
		if network != "udp" || address != "" || remote != metadata.AddrPort() {
			t.Fatalf("unexpected listen arguments: %s %q %s", network, address, remote)
		}
		if calls == 1 {
			return conflict, nil
		}
		if calls != 2 {
			t.Fatalf("unexpected allocation %d", calls)
		}
		// Keeping the conflicting socket open prevents immediate port reuse.
		if err := conflict.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("conflicting socket closed before replacement: %v", err)
		}
		safe = listenUDP(t)
		return safe, nil
	})
	pc, err := d.listenPacketContext(context.Background(), metadata, dialer)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if calls != 2 {
		t.Fatalf("allocations = %d, want 2", calls)
	}
	requireClosed(t, conflict)

	// Exercise the accepted connection through the production packet wrapper.
	echo := listenUDP(t)
	deadline := time.Now().Add(2 * time.Second)
	if err := pc.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := echo.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	payload := []byte("safe UDP reply")
	if _, err := pc.WriteTo(payload, echo.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, peer, err := echo.ReadFrom(buf)
	if err != nil || string(buf[:n]) != string(payload) {
		t.Fatalf("echo request = %q, %v", buf[:n], err)
	}
	if peer.String() != safe.LocalAddr().String() {
		t.Fatalf("request peer = %s, want %s", peer, safe.LocalAddr())
	}
	if _, err := echo.WriteTo(buf[:n], peer); err != nil {
		t.Fatal(err)
	}
	n, peer, err = pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != string(payload) || peer.String() != echo.LocalAddr().String() {
		t.Fatalf("UDP reply = %q from %v, error %v", buf[:n], peer, err)
	}
	accepted := udpMetadata(safe)
	if !errors.Is(d.loopBack.CheckPacketConn(accepted), loopback.ErrReject) {
		t.Fatal("accepted socket was not registered")
	}
	if err := d.loopBack.CheckPacketConn(metadata); err != nil {
		t.Fatalf("discarded socket was registered: %v", err)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.loopBack.CheckPacketConn(accepted); err != nil {
		t.Fatalf("closed socket is still registered: %v", err)
	}
}

// Allows deterministic exhaustion while each allocation still owns a real socket.
type reportedPacketConn struct {
	net.PacketConn
	address net.Addr
}

func (pc reportedPacketConn) LocalAddr() net.Addr { return pc.address }

func TestDirectUDPPortCollisionCleanup(t *testing.T) {
	listenErr := errors.New("listen failed")
	for _, test := range []string{"listen error", "canceled", "exhausted", "already canceled"} {
		t.Run(test, func(t *testing.T) {
			first := listenUDP(t)
			metadata := udpMetadata(first)
			d := NewDirect()
			d.loopBack = &loopback.Detector{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test == "already canceled" {
				cancel()
			}
			var allocated []net.PacketConn
			calls := 0
			dialer := packetListenFunc(func(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
				calls++
				if test == "listen error" && calls == 2 {
					return nil, listenErr
				}
				var pc net.PacketConn = first
				if calls > 1 {
					pc = reportedPacketConn{PacketConn: listenUDP(t), address: first.LocalAddr()}
				}
				allocated = append(allocated, pc)
				if test == "canceled" {
					cancel()
				}
				return pc, nil
			})
			pc, err := d.listenPacketContext(ctx, metadata, dialer)
			if pc != nil || err == nil {
				t.Fatalf("connection = %v, error = %v; want failure", pc, err)
			}
			switch test {
			case "listen error":
				if calls != 2 || !errors.Is(err, listenErr) {
					t.Fatalf("calls = %d, error = %v", calls, err)
				}
			case "canceled", "already canceled":
				wantCalls := 1
				if test == "already canceled" {
					wantCalls = 0
				}
				if calls != wantCalls || !errors.Is(err, context.Canceled) {
					t.Fatalf("calls = %d, error = %v", calls, err)
				}
			case "exhausted":
				if calls != 8 || !errors.Is(err, loopback.ErrReject) {
					t.Fatalf("calls = %d, error = %v", calls, err)
				}
			}
			for _, discarded := range allocated {
				requireClosed(t, discarded)
			}
			if err := d.loopBack.CheckPacketConn(metadata); err != nil {
				t.Fatalf("failed allocation was registered: %v", err)
			}
		})
	}
}

func TestDirectUDPNoPortCollision(t *testing.T) {
	for _, test := range []string{"different port", "remote source", "disabled detector"} {
		t.Run(test, func(t *testing.T) {
			native := listenUDP(t)
			metadata := udpMetadata(native)
			d := NewDirect()
			d.loopBack = &loopback.Detector{}
			switch test {
			case "different port":
				metadata.SrcPort = uint16(listenUDP(t).LocalAddr().(*net.UDPAddr).Port)
			case "remote source":
				metadata.SrcIP = netip.MustParseAddr("192.0.2.1")
			case "disabled detector":
				d.loopBack = nil
			}
			calls := 0
			pc, err := d.listenPacketContext(context.Background(), metadata, packetListenFunc(func(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
				calls++
				return native, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			if calls != 1 {
				t.Fatalf("allocations = %d, want 1", calls)
			}
		})
	}
}
