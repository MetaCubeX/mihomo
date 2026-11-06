//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/tailscale/tailcfg"
)

func (t *Tailscale) SupportICMP() bool { return true }

// PingICMP probes the destination itself (PingICMP, not disco or TSMP). The
// caller may return an echo reply only on success. This is echo proxying, not
// raw ICMP tunneling: the backend chooses its own identifier and payload.
func (t *Tailscale) PingICMP(ctx context.Context, destination netip.Addr) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := contextutils.AfterFunc(t.ctx, cancel)
	defer stop()
	if err := t.ensureStarted(ctx); err != nil {
		return err
	}
	// Wait for Running, including when the destination is this embedded node.
	if _, err := t.server.Netstack(ctx); err != nil {
		return err
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	result, err := lc.Ping(ctx, destination, tailcfg.PingICMP)
	if err != nil {
		return err
	}
	if result == nil {
		return fmt.Errorf("tailscale ICMP probe returned no result")
	}
	// Tailscale reports its own active address instead of sending to a peer.
	if result.IsLocalIP {
		return nil
	}
	if result.Err != "" {
		return fmt.Errorf("tailscale ICMP: %s", result.Err)
	}
	return nil
}
