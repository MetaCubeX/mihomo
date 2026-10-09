package tunnel

import (
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

func TestHandleUDPUsesListenerAddressInSessionKey(t *testing.T) {
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51823}
	packetConnA := &testPacketConn{localAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820}}
	packetConnB := &testPacketConn{localAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51821}}
	capture := &testTunnel{}

	listenerA := &PacketConn{target: socks5.ParseAddr("198.51.100.20:51820")}
	listenerB := &PacketConn{target: socks5.ParseAddr("198.51.100.21:51821")}
	listenerA.handleUDP(packetConnA, capture, []byte("a"), source)
	listenerB.handleUDP(packetConnB, capture, []byte("b"), source)
	listenerA.handleUDP(packetConnA, capture, []byte("c"), source)

	if len(capture.packets) != 3 {
		t.Fatalf("captured %d packets, want 3", len(capture.packets))
	}
	if capture.packets[0].Key() == capture.packets[1].Key() {
		t.Fatalf("session keys collide across listeners: %q", capture.packets[0].Key())
	}
	if capture.packets[0].Key() != capture.packets[2].Key() {
		t.Errorf("session key changed within one listener: %q != %q", capture.packets[0].Key(), capture.packets[2].Key())
	}
	if got, want := capture.packets[0].Key(), "127.0.0.1:51820|192.0.2.1:51823"; got != want {
		t.Errorf("session key = %q, want %q", got, want)
	}

	for i, packet := range capture.packets {
		if got := packet.Metadata().SourceAddress(); got != source.String() {
			t.Errorf("packet %d source = %q, want %q", i, got, source)
		}
	}
	if got := capture.packets[0].Metadata().InPort; got != 51820 {
		t.Errorf("first packet inbound port = %d, want 51820", got)
	}
	if got := capture.packets[1].Metadata().InPort; got != 51821 {
		t.Errorf("second packet inbound port = %d, want 51821", got)
	}

	if _, err := capture.packets[0].WriteBack([]byte("response"), nil); err != nil {
		t.Fatalf("write back: %v", err)
	}
	if got := packetConnA.writeAddr.String(); got != source.String() {
		t.Errorf("write-back address = %q, want %q", got, source)
	}
}

type testTunnel struct {
	packets []C.PacketAdapter
}

func (*testTunnel) HandleTCPConn(net.Conn, *C.Metadata) {}

func (t *testTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	t.packets = append(t.packets, C.NewPacketAdapter(packet, metadata))
}

func (*testTunnel) NatTable() C.NatTable { return nil }

type testPacketConn struct {
	localAddr net.Addr
	writeAddr net.Addr
}

func (*testPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }

func (c *testPacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	c.writeAddr = addr
	return len(payload), nil
}

func (*testPacketConn) Close() error                     { return nil }
func (c *testPacketConn) LocalAddr() net.Addr            { return c.localAddr }
func (*testPacketConn) SetDeadline(time.Time) error      { return nil }
func (*testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*testPacketConn) SetWriteDeadline(time.Time) error { return nil }
