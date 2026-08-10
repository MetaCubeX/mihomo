//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"testing"
)

func TestTailscaleSystemPacketListenerWithDialerProxy(t *testing.T) {
	outbound, err := NewTailscale(TailscaleOption{
		BasicOption: BasicOption{DialerProxy: "missing"},
		Name:        "test",
		StateDir:    "tailscale-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := outbound.Close(); err != nil {
			t.Error(err)
		}
	})

	packetConn, err := outbound.server.SystemPacketListener(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := packetConn.Close(); err != nil {
		t.Error(err)
	}
}
