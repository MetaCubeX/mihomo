//go:build darwin

package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/loopback"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

var proofPayload = []byte("mihomo-real-reply-handler-proof")
var proofClientIP = netip.MustParseAddr("198.19.255.1")
var proofRemote = netip.MustParseAddrPort("192.0.2.123:443")

func proofEnvironment(t *testing.T) (*os.File, string, string) {
	t.Helper()
	n, err := strconv.Atoi(os.Getenv("MIHOMO_PROOF_TUN_FD"))
	if err != nil {
		t.Skip("requires isolated TUN proof runner")
	}
	if ip := os.Getenv("MIHOMO_PROOF_CLIENT_IP"); ip != "" {
		proofClientIP = netip.MustParseAddr(ip)
	}
	return os.NewFile(uintptr(n), "isolated-utun"), os.Getenv("MIHOMO_PROOF_IFACE"), os.Getenv("MIHOMO_PROOF_IP")
}

func proofFrame(data []byte, source netip.AddrPort, port uint16) []byte {
	b := make([]byte, 4+20+8+len(data))
	binary.BigEndian.PutUint32(b[:4], 2) // Darwin AF_INET.
	ip := b[4:24]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(b)-4))
	src, dst := source.Addr().Unmap().As4(), proofClientIP.As4()
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))
	udp := b[24:]
	binary.BigEndian.PutUint16(udp[0:2], source.Port())
	binary.BigEndian.PutUint16(udp[2:4], port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], data) // IPv4 UDP checksum zero is valid.
	return b
}

type proofWriter struct {
	tun   *os.File
	port  uint16
	count atomic.Int64
	limit int64
}

type proofPacketConn struct{ N.EnhancePacketConn }

func (*proofPacketConn) Chains() C.Chain                               { return C.Chain{"DIRECT"} }
func (*proofPacketConn) ProviderChains() C.Chain                       { return nil }
func (*proofPacketConn) AppendToChains(C.ProxyAdapter)                 {}
func (*proofPacketConn) RemoteDestination() string                     { return "" }
func (*proofPacketConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

func (w *proofWriter) WriteBack(data []byte, addr net.Addr) (int, error) {
	n := w.count.Add(1)
	if n >= 64 {
		return 0, errors.New("proof 64-packet safety limit")
	}
	_, err := w.tun.Write(proofFrame(data, addr.(*net.UDPAddr).AddrPort(), w.port))
	if err != nil {
		return 0, err
	}
	if n >= w.limit {
		return len(data), errors.New("proof completed")
	}
	return len(data), nil
}

type checkedPacketAllocator interface {
	ListenPacket(*C.Metadata, func() (C.PacketConn, error)) (C.PacketConn, error)
}

func proofDirectSocket(t *testing.T, iface string, port uint16, remote netip.AddrPort, forceCollision bool) C.PacketConn {
	t.Helper()
	metadata := &C.Metadata{SrcIP: proofClientIP, SrcPort: port, DstIP: remote.Addr(), DstPort: remote.Port()}
	detector := loopback.NewDetector()
	if detector == nil {
		t.Fatal("isolated regression requires loopback detection; unset DISABLE_LOOPBACK_DETECTOR")
	}
	allocations := 0
	listen := func() (C.PacketConn, error) {
		address := ":0"
		if allocations == 0 && forceCollision {
			address = fmt.Sprintf(":%d", port)
		}
		allocations++
		native, err := dialer.ListenPacket(context.Background(), "udp", address, remote, dialer.WithInterface(iface))
		if err != nil {
			return nil, err
		}
		return &proofPacketConn{N.NewEnhancePacketConn(native)}, nil
	}
	var pc C.PacketConn
	var err error
	allocator, protected := any(detector).(checkedPacketAllocator)
	if protected {
		pc, err = allocator.ListenPacket(metadata, listen)
	} else {
		// Reproduce v1.19.32 DIRECT's pre-check -> allocate -> register order.
		err = detector.CheckPacketConn(metadata)
		if err == nil {
			pc, err = listen()
		}
		if err == nil {
			pc = detector.NewPacketConn(pc)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("guard enabled=%t, socket allocations=%d, source port=%d, outbound=%s", protected, allocations, port, pc.LocalAddr())
	if protected && pc.LocalAddr().(*net.UDPAddr).Port == int(port) {
		t.Fatal("guard returned a conflicting port")
	}
	return pc
}

func proofHandler(t *testing.T, pc C.PacketConn, writer *proofWriter, port uint16) (*statistic.TrackerInfo, <-chan struct{}) {
	t.Helper()
	metadata := &C.Metadata{SrcIP: proofClientIP, SrcPort: port, DstIP: proofRemote.Addr(), DstPort: 443}
	tracked := statistic.NewUDPTracker(pc, &statistic.Manager{}, metadata, nil, 0, 0, false)
	done := make(chan struct{})
	go func() {
		handleUDPToLocal(writer, tracked, newPacketSender(), "isolated-proof", proofRemote)
		close(done)
	}()
	t.Cleanup(func() { pc.Close(); <-done })
	return tracked.TrackerInfo, done
}

func TestTUNReplyCannotReenterOutbound(t *testing.T) {
	tun, iface, _ := proofEnvironment(t)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(proofClientIP.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(client.LocalAddr().(*net.UDPAddr).Port)
	client.Close() // Force a reproducible kernel allocation collision after client exit.
	pc := proofDirectSocket(t, iface, port, proofRemote, true)
	t.Logf("outbound local address: %s", pc.LocalAddr())
	writer := &proofWriter{tun: tun, port: port, limit: 64}
	tracked, done := proofHandler(t, pc, writer, port)
	started := time.Now()
	if _, err := tun.Write(proofFrame(proofPayload, proofRemote, port)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		pc.Close()
		<-done
	}
	t.Logf("one injected packet -> real handler writebacks=%d, download bytes=%d, elapsed=%s", writer.count.Load(), tracked.DownloadTotal.Load(), time.Since(started))
	if writer.count.Load() != 0 {
		t.Fatalf("TUN client reply entered outbound socket and recycled %d times", writer.count.Load())
	}
}

func TestUDPForwardingAfterPortGuard(t *testing.T) {
	tun, iface, physicalIP := proofEnvironment(t)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(proofClientIP.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	port := uint16(client.LocalAddr().(*net.UDPAddr).Port)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(physicalIP)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	remote := server.LocalAddr().(*net.UDPAddr).AddrPort()
	pc := proofDirectSocket(t, iface, port, remote, false)
	writer := &proofWriter{tun: tun, port: port, limit: 1}
	tracked, done := proofHandler(t, pc, writer, port)
	server.SetDeadline(time.Now().Add(time.Second))
	client.SetDeadline(time.Now().Add(time.Second))
	if _, err := pc.WriteTo(proofPayload, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1024)
	n, peer, err := server.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.WriteToUDP(b[:n], peer); err != nil {
		t.Fatal(err)
	}
	n, clientPeer, err := client.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(b[:n]) != string(proofPayload) {
		t.Fatalf("payload changed: %q", b[:n])
	}
	if clientPeer.AddrPort().Addr().Unmap() != remote.Addr().Unmap() || clientPeer.Port != int(remote.Port()) {
		t.Fatalf("reply source changed: %s, want %s", clientPeer, remote)
	}
	<-done
	t.Logf("real local UDP echo -> client replies=1; writebacks=%d, download bytes=%d; client port=%d, outbound=%s", writer.count.Load(), tracked.DownloadTotal.Load(), port, pc.LocalAddr())
	if writer.count.Load() != 1 {
		t.Fatal("legitimate UDP reply was not delivered exactly once")
	}
}
