package inbound_test

import (
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"

	"github.com/stretchr/testify/assert"
)

var singMuxProtocolList = []string{"smux", "yamux"} // don't test "h2mux" because it has some confused bugs

// notCloseProxyAdapter is a proxy adapter that does not close the underlying outbound.ProxyAdapter.
// The outbound.SingMux will close the underlying outbound.ProxyAdapter when it is closed, but we don't want to close it.
// The underlying outbound.ProxyAdapter should only be closed by the caller of testSingMux.
type notCloseProxyAdapter struct {
	outbound.ProxyAdapter
}

func (n *notCloseProxyAdapter) Close() error {
	return nil
}

func testSingMux(t *testing.T, tunnel *TestTunnel, out outbound.ProxyAdapter) {
	t.Run("singmux", func(t *testing.T) {
		for _, protocol := range singMuxProtocolList {
			protocol := protocol
			t.Run(protocol, func(t *testing.T) {
				t.Parallel()
				singMuxOption := outbound.SingMuxOption{
					Enabled:  true,
					Protocol: protocol,
				}
				out, err := outbound.NewSingMux(singMuxOption, &notCloseProxyAdapter{out})
				if !assert.NoError(t, err) {
					return
				}
				defer out.Close()

				tunnel.DoTest(t, out)
			})
		}
	})
}
