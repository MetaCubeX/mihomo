package ebpf

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestDecisionObserverOnlyBypassesFinalDirect(t *testing.T) {
	writer := &memoryDestinationMap{}
	offloader := NewOffloader(writer)
	observe := DecisionObserver(offloader, 0)
	ip := netip.MustParseAddr("203.0.113.42")
	metadata := &C.Metadata{Type: C.EBPF, DstIP: ip, Host: "decision.example"}
	direct := adapter.NewProxy(outbound.NewDirect())
	observe(metadata, direct)
	require.Contains(t, writer.entries, ip)
	reject := adapter.NewProxy(outbound.NewReject())
	observe(metadata, reject)
	require.NotContains(t, writer.entries, ip)
}
