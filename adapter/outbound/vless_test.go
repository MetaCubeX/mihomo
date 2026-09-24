package outbound

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseVlessAddrUsesNativeMuxCommandForMuxCoolCarrier(t *testing.T) {
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.INNER,
		Host:    muxCoolDestination,
		DstPort: muxCoolPort,
	}

	destination := parseVlessAddr(metadata, false)
	if !destination.Mux {
		t.Fatal("mux.cool carrier did not select the native VLESS Mux command")
	}
}

func TestParseVlessAddrDoesNotUseMuxCommandForOrdinaryTCP(t *testing.T) {
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    muxCoolDestination,
		DstPort: muxCoolPort + 1,
	}

	destination := parseVlessAddr(metadata, false)
	if destination.Mux {
		t.Fatal("ordinary TCP destination selected the native VLESS Mux command")
	}
}
