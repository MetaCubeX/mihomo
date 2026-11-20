package inbound

import (
	"context"
	"net"
	"testing"
)

func TestListenIPv4Wildcard(t *testing.T) {
	listener, err := NewListenConfig().Listen(context.Background(), "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if address := listener.Addr().(*net.TCPAddr).AddrPort().Addr(); !address.Is4() {
		t.Fatalf("IPv4 wildcard listener bound %s", address)
	}
}

func TestListenPacketIPv4Wildcard(t *testing.T) {
	listener, err := NewListenConfig().ListenPacket(context.Background(), "udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if address := listener.LocalAddr().(*net.UDPAddr).AddrPort().Addr(); !address.Is4() {
		t.Fatalf("IPv4 wildcard packet listener bound %s", address)
	}
}
