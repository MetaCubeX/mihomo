//go:build with_gvisor

package tunnel

import (
	"context"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"

	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/sing/common"
)

func TestLifecycleGVisorHasNoNativeCloseCapability(t *testing.T) {
	// Type/unwrap coverage only: the zero-value adapter performs no socket I/O.
	conn := icontext.NewConnContext(new(gonet.TCPConn), &C.Metadata{}).Conn()
	if _, ok := common.Cast[interface {
		CancelOnClose(context.CancelFunc) func() bool
	}](conn); ok {
		t.Fatal("gVisor adapter unexpectedly exposes the native cancellation hook")
	}
}
