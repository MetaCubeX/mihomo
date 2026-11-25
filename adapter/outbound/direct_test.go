package outbound

import (
	"context"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestDirectUDPReplyPreservesPayloadAndPeer(t *testing.T) {
	for _, tc := range []struct {
		network string
		address string
	}{
		{"udp4", "127.0.0.1:0"},
		{"udp6", "[::1]:0"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			server, err := net.ListenPacket(tc.network, tc.address)
			if err != nil {
				if tc.network == "udp6" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer server.Close()
			client, err := net.ListenPacket(tc.network, tc.address)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			remote := server.LocalAddr().(*net.UDPAddr).AddrPort()
			source := client.LocalAddr().(*net.UDPAddr).AddrPort()
			metadata := &C.Metadata{
				NetWork: C.UDP,
				SrcIP:   source.Addr(), SrcPort: source.Port(),
				DstIP: remote.Addr(), DstPort: remote.Port(),
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			pc, err := NewDirect().ListenPacketContext(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			deadline := time.Now().Add(time.Second)
			server.SetDeadline(deadline)
			pc.SetDeadline(deadline)
			payload := []byte("direct-udp-reply")
			if _, err := pc.WriteTo(payload, server.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 1024)
			n, peer, err := server.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.WriteTo(buffer[:n], peer); err != nil {
				t.Fatal(err)
			}
			n, peer, err = pc.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if string(buffer[:n]) != string(payload) {
				t.Fatalf("payload changed: %q", buffer[:n])
			}
			got := peer.(*net.UDPAddr).AddrPort()
			if got.Addr().Unmap() != remote.Addr().Unmap() || got.Port() != remote.Port() {
				t.Fatalf("reply peer changed: %s, want %s", got, remote)
			}
		})
	}
}
