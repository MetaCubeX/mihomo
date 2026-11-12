package loopback

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

type testPacketConn struct{ N.EnhancePacketConn }

func (*testPacketConn) Chains() C.Chain                               { return nil }
func (*testPacketConn) ProviderChains() C.Chain                       { return nil }
func (*testPacketConn) AppendToChains(C.ProxyAdapter)                 {}
func (*testPacketConn) RemoteDestination() string                     { return "" }
func (*testPacketConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

func nativePacket(t *testing.T, network, address string) C.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return &testPacketConn{N.NewEnhancePacketConn(pc)}
}

func releasedPort(t *testing.T) uint16 {
	t.Helper()
	pc := nativePacket(t, "udp4", "127.0.0.1:0")
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	pc.Close()
	return port
}

func source(port uint16) *C.Metadata {
	return &C.Metadata{SrcIP: netip.MustParseAddr("127.0.0.1"), SrcPort: port}
}

func TestPortChosenAfterPrecheckIsRejectedAndReallocated(t *testing.T) {
	detector := NewDetector()
	safe := nativePacket(t, "udp4", "127.0.0.1:0")
	port := releasedPort(t)
	calls := 0
	var rejected C.PacketConn
	conn, err := detector.ListenPacket(source(port), func() (C.PacketConn, error) {
		calls++
		if calls == 1 {
			rejected = nativePacket(t, "udp4", fmt.Sprintf(":%d", port))
			return rejected, nil
		}
		return safe, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if calls != 2 || conn.LocalAddr().(*net.UDPAddr).Port == int(port) {
		t.Fatalf("unsafe allocation accepted: calls=%d addr=%s", calls, conn.LocalAddr())
	}
	if _, err := rejected.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("rejected socket not closed: %v", err)
	}
}

func TestRepeatedCollisionsStopAfterBoundedAttempts(t *testing.T) {
	detector := NewDetector()
	port := releasedPort(t)
	calls := 0
	conn, err := detector.ListenPacket(source(port), func() (C.PacketConn, error) {
		calls++
		return nativePacket(t, "udp4", fmt.Sprintf(":%d", port)), nil
	})
	if conn != nil || !errors.Is(err, ErrReject) || calls != 4 {
		t.Fatalf("unbounded or accepted collision: conn=%v err=%v calls=%d", conn, err, calls)
	}
	if err := detector.CheckPacketConn(source(port)); err != nil {
		t.Fatalf("closed sockets left registered: %v", err)
	}
}

func TestExistingConflictIsRejectedWithoutAllocation(t *testing.T) {
	detector := NewDetector()
	existing := detector.NewPacketConn(nativePacket(t, "udp4", "127.0.0.1:0"))
	defer existing.Close()
	port := uint16(existing.LocalAddr().(*net.UDPAddr).Port)
	calls := 0
	_, err := detector.ListenPacket(source(port), func() (C.PacketConn, error) { calls++; return nil, errors.New("must not allocate") })
	if !errors.Is(err, ErrReject) || calls != 0 {
		t.Fatalf("existing conflict retried: err=%v calls=%d", err, calls)
	}
}

func TestSamePortRegistrationsSurviveClosingOneSocket(t *testing.T) {
	detector := NewDetector()
	pc4 := nativePacket(t, "udp4", "127.0.0.1:0")
	port := uint16(pc4.LocalAddr().(*net.UDPAddr).Port)
	pc6 := nativePacket(t, "udp6", fmt.Sprintf("[::1]:%d", port))
	conn4, conn6 := detector.NewPacketConn(pc4), detector.NewPacketConn(pc6)
	defer conn4.Close()
	defer conn6.Close()
	conn4.Close()
	if !errors.Is(detector.CheckPacketConn(source(port)), ErrReject) {
		t.Fatal("closing one socket erased other same-port registration")
	}
	conn6.Close()
	if err := detector.CheckPacketConn(source(port)); err != nil {
		t.Fatalf("final registration leaked: %v", err)
	}
}

func TestConflictAcrossDirectInstances(t *testing.T) {
	first, second := NewDetector(), NewDetector()
	conn := first.NewPacketConn(nativePacket(t, "udp4", "127.0.0.1:0"))
	defer conn.Close()
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	if !errors.Is(second.CheckPacketConn(source(port)), ErrReject) {
		t.Fatal("second DIRECT instance cannot see shared UDP namespace")
	}
}

func TestOwnPortCollisionDoesNotDependOnLocalIPLookup(t *testing.T) {
	detector := NewDetector()
	safe := nativePacket(t, "udp4", "127.0.0.1:0")
	port := releasedPort(t)
	metadata := &C.Metadata{SrcIP: netip.MustParseAddr("192.0.2.9"), SrcPort: port}
	calls := 0
	conn, err := detector.ListenPacket(metadata, func() (C.PacketConn, error) {
		calls++
		if calls == 1 {
			return nativePacket(t, "udp4", fmt.Sprintf(":%d", port)), nil
		}
		return safe, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if calls != 2 || conn.LocalAddr().(*net.UDPAddr).Port == int(port) {
		t.Fatal("own-port collision escaped due to source IP lookup")
	}
}

func TestDisabledDetectorPreservesAllocatorError(t *testing.T) {
	var detector *Detector
	want := errors.New("listen failed")
	calls := 0
	conn, err := detector.ListenPacket(source(12345), func() (C.PacketConn, error) {
		calls++
		return nil, want
	})
	if conn != nil || err != want || calls != 1 {
		t.Fatalf("disabled detector changed allocation: conn=%v err=%v calls=%d", conn, err, calls)
	}
}
