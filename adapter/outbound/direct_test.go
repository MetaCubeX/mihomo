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

type directTestDialer struct {
	C.Dialer
	listen func() (net.PacketConn, error)
}

func (d directTestDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return d.listen()
}

func directTestSocket(t *testing.T, address string) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func directTestMetadata(pc net.PacketConn, source string) *C.Metadata {
	return &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		SrcIP:   netip.MustParseAddr(source),
		SrcPort: uint16(pc.LocalAddr().(*net.UDPAddr).Port),
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: 443,
	}
}

func requireDirectSocketClosed(t *testing.T, pc net.PacketConn) {
	t.Helper()
	_, err := pc.WriteTo([]byte("closed"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("colliding socket was not closed: %v", err)
	}
}

func TestDirectUDPSourcePortCollision(t *testing.T) {
	sources := []string{"127.0.0.1", "::ffff:127.0.0.1"}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		if prefix, ok := address.(*net.IPNet); ok && prefix.IP.To4() != nil && !prefix.IP.IsLoopback() {
			sources = append(sources, prefix.IP.String())
		}
	}
	for _, source := range sources {
		t.Run(source, func(t *testing.T) {
			collision := directTestSocket(t, "127.0.0.1:0")
			available := directTestSocket(t, "127.0.0.1:0")
			calls := 0
			pc, err := listenDirectPacket(context.Background(), directTestMetadata(collision, source), directTestDialer{
				listen: func() (net.PacketConn, error) {
					calls++
					if calls == 1 {
						return collision, nil
					}
					return available, nil
				},
			})
			if err != nil || pc != available || calls != 2 {
				t.Fatalf("unsafe socket returned: got %v, err %v, calls %d", pc, err, calls)
			}
			requireDirectSocketClosed(t, collision)

			peer := directTestSocket(t, "127.0.0.1:0")
			_ = peer.SetDeadline(time.Now().Add(time.Second))
			_ = pc.SetDeadline(time.Now().Add(time.Second))
			if _, err := pc.WriteTo([]byte("ping"), peer.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 32)
			n, from, err := peer.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != "ping" {
				t.Fatalf("outbound UDP failed: %v", err)
			}
			if _, err := peer.WriteTo([]byte("pong"), from); err != nil {
				t.Fatal(err)
			}
			n, _, err = pc.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != "pong" {
				t.Fatalf("return UDP failed: %v", err)
			}
		})
	}
}

func TestDirectUDPSourcePortListenError(t *testing.T) {
	expected := errors.New("listen failed")
	got, err := listenDirectPacket(context.Background(), &C.Metadata{}, directTestDialer{
		listen: func() (net.PacketConn, error) { return nil, expected },
	})
	if got != nil || !errors.Is(err, expected) {
		t.Fatalf("listen error was not preserved: pc %v, err %v", got, err)
	}
}

func TestDirectUDPSourcePortRemoteClient(t *testing.T) {
	pc := directTestSocket(t, "127.0.0.1:0")
	got, err := listenDirectPacket(context.Background(), directTestMetadata(pc, "203.0.113.1"), directTestDialer{
		listen: func() (net.PacketConn, error) { return pc, nil },
	})
	if err != nil || got != pc {
		t.Fatalf("nonlocal client should retain its socket: %v", err)
	}
}

func TestDirectUDPSourcePortRetryLimit(t *testing.T) {
	first := directTestSocket(t, "127.0.0.1:0")
	address := first.LocalAddr().String()
	metadata := directTestMetadata(first, "127.0.0.1")
	var sockets []net.PacketConn
	pc, err := listenDirectPacket(context.Background(), metadata, directTestDialer{
		listen: func() (net.PacketConn, error) {
			if len(sockets) == 0 {
				sockets = append(sockets, first)
				return first, nil
			}
			if len(sockets) >= 16 {
				t.Fatal("unbounded collision retry")
			}
			next := directTestSocket(t, address)
			sockets = append(sockets, next)
			return next, nil
		},
	})
	if pc != nil || !errors.Is(err, loopback.ErrReject) || len(sockets) < 2 {
		t.Fatalf("persistent collisions must fail closed: pc %v, err %v, attempts %d", pc, err, len(sockets))
	}
	for _, socket := range sockets {
		requireDirectSocketClosed(t, socket)
	}
}

func TestDirectUDPSourcePortCancellation(t *testing.T) {
	pc := directTestSocket(t, "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	got, err := listenDirectPacket(ctx, directTestMetadata(pc, "127.0.0.1"), directTestDialer{
		listen: func() (net.PacketConn, error) {
			calls++
			cancel()
			return pc, nil
		},
	})
	if got != nil || !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled retry continued: pc %v, err %v, calls %d", got, err, calls)
	}
	requireDirectSocketClosed(t, pc)
}
