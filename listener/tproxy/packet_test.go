package tproxy

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/nat"
	C "github.com/metacubex/mihomo/constant"
)

type fakeTunnel struct {
	C.Tunnel
	nat     C.NatTable
	packets chan []byte
}

func (t *fakeTunnel) NatTable() C.NatTable { return t.nat }

func (t *fakeTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	t.packets <- append([]byte(nil), packet.Data()...)
	packet.Drop()
}

func TestServeLocalConnIdleExit(t *testing.T) {
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()

	rAddr := netip.MustParseAddrPort("203.0.113.1:53")
	lAddr := netip.MustParseAddrPort("192.0.2.1:40000")
	table := nat.New()
	table.GetOrCreate(lAddr.String(), func() C.PacketSender { return nil })
	table.AddForLocalConn(lAddr.String(), rAddr.String(), lc)
	tunnel := &fakeTunnel{nat: table, packets: make(chan []byte, 8)}

	done := make(chan struct{})
	go func() {
		serveLocalConn(lc, rAddr, lAddr, tunnel, 100*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("reader goroutine still running after the idle timeout")
	}
	if got := table.GetForLocalConn(lAddr.String(), rAddr.String()); got != nil {
		t.Fatal("NAT entry was not removed on idle exit")
	}
	if _, err := lc.WriteToUDP([]byte("x"), lc.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatal("socket was not closed on idle exit")
	}
	select {
	case p := <-tunnel.packets:
		t.Fatalf("empty/failed read was handed to the tunnel: %q", p)
	default:
	}
}

func TestWriteBackKeepsLocalConnAlive(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	lc, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()

	old := localConnIdleTimeout
	localConnIdleTimeout = 300 * time.Millisecond
	defer func() { localConnIdleTimeout = old }()

	rAddr := netip.MustParseAddrPort("203.0.113.1:53")
	lAddr := netip.MustParseAddrPort("192.0.2.1:40000")
	table := nat.New()
	table.GetOrCreate(lAddr.String(), func() C.PacketSender { return nil })
	table.AddForLocalConn(lAddr.String(), rAddr.String(), lc)
	tunnel := &fakeTunnel{nat: table, packets: make(chan []byte, 8)}

	done := make(chan struct{})
	go func() {
		serveLocalConn(lc, rAddr, lAddr, tunnel, localConnIdleTimeout)
		close(done)
	}()

	// replies keep going out for longer than the idle timeout while nothing is read
	pkt := &packet{lAddr: lAddr, tunnel: tunnel}
	for i := 0; i < 8; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, err := pkt.WriteBack([]byte("x"), net.UDPAddrFromAddrPort(rAddr)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		select {
		case <-done:
			t.Fatalf("local conn was released while replies were still being written (write %d)", i)
		default:
		}
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("reader goroutine still running after the replies stopped")
	}
}
