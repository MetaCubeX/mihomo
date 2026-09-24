package inbound_test

import (
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

var singMuxProtocolList = []string{"h2mux", "smux", "yamux"}
var singMuxProtocolListLong = []string{"yamux"} // don't test "smux", "h2mux" because it has some confused bugs

// notCloseProxyAdapter is a proxy adapter that does not close the underlying outbound.ProxyAdapter.
// Multiplexing wrappers close their underlying ProxyAdapter, but the test owner keeps it alive.
// The underlying outbound.ProxyAdapter should only be closed by the caller of testSingMux.
type notCloseProxyAdapter struct {
	outbound.ProxyAdapter
}

func testMuxCool(t *testing.T, tunnel *TestTunnel, out outbound.ProxyAdapter) {
	t.Run("mux.cool", func(t *testing.T) {
		muxCool, err := outbound.NewMuxCool(outbound.MuxCoolOption{
			Enabled:         true,
			XUDPProxyUDP443: "allow",
		}, &notCloseProxyAdapter{out})
		if !assert.NoError(t, err) {
			return
		}
		defer muxCool.Close()

		tunnel.DoSequentialTest(t, muxCool)
		tunnel.DoConcurrentTest(t, muxCool)
	})
}

func (n *notCloseProxyAdapter) Close() error {
	return nil
}

func testSingMux(t *testing.T, tunnel *TestTunnel, out outbound.ProxyAdapter) {
	t.Run("singmux", func(t *testing.T) {
		for _, protocol := range singMuxProtocolList {
			protocol := protocol
			t.Run(protocol, func(t *testing.T) {
				singMuxOption := outbound.SingMuxOption{
					Enabled:  true,
					Protocol: protocol,
				}
				out, err := outbound.NewSingMux(singMuxOption, &notCloseProxyAdapter{out})
				if !assert.NoError(t, err) {
					return
				}
				defer out.Close()

				tunnel.DoSequentialTest(t, out)
				if slices.Contains(singMuxProtocolListLong, protocol) {
					tunnel.DoConcurrentTest(t, out)
				}
			})
		}
	})
}
