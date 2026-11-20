package outbound

import (
	"net"
	"testing"
)

func listenLocalUDP(t *testing.T) net.PacketConn {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

func TestListenPacketAvoidPort(t *testing.T) {
	t.Run("different port", func(t *testing.T) {
		first := listenLocalUDP(t)
		defer first.Close()
		port := uint16(first.LocalAddr().(*net.UDPAddr).Port)

		calls := 0
		pc, err := listenPacketAvoidPort(func() (net.PacketConn, error) {
			calls++
			return first, nil
		}, port+1)
		if err != nil {
			t.Fatal(err)
		}
		if pc != first || calls != 1 {
			t.Fatalf("expected the first conn without retry, got calls=%d", calls)
		}
	})

	t.Run("same port", func(t *testing.T) {
		first := listenLocalUDP(t)
		port := uint16(first.LocalAddr().(*net.UDPAddr).Port)

		calls := 0
		pc, err := listenPacketAvoidPort(func() (net.PacketConn, error) {
			calls++
			if calls == 1 {
				return first, nil
			}
			return listenLocalUDP(t), nil
		}, port)
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		if calls != 2 {
			t.Fatalf("expected one retry, got calls=%d", calls)
		}
		if got := pc.LocalAddr().(*net.UDPAddr).Port; got == int(port) {
			t.Fatalf("returned conn is still bound to the source port %d", port)
		}
		if err := first.Close(); err == nil {
			t.Fatal("expected the colliding conn to be closed")
		}
	})
}
