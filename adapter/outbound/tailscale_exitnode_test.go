//go:build with_gvisor && !no_tailscale

package outbound

import (
	"net/netip"
	"testing"

	"github.com/metacubex/tailscale/tailcfg"

	"github.com/stretchr/testify/assert"
)

func TestTailscaleOffersExitNode(t *testing.T) {
	node := func(allowedIPs ...string) *tailcfg.Node {
		n := &tailcfg.Node{}
		for _, ip := range allowedIPs {
			n.AllowedIPs = append(n.AllowedIPs, netip.MustParsePrefix(ip))
		}
		return n
	}
	peer := node("100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	subnetRouter := node("100.64.0.3/32", "192.168.1.0/24")
	exitNode := node("100.64.0.1/32", "0.0.0.0/0", "::/0")

	assert.False(t, tailscaleOffersExitNode(nil))
	assert.False(t, tailscaleOffersExitNode([]*tailcfg.Node{peer, subnetRouter}))
	assert.True(t, tailscaleOffersExitNode([]*tailcfg.Node{peer, exitNode}))
}
