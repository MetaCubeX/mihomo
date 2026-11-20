//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"time"
)

func retryTailscaleExitNode(ctx context.Context, apply func(context.Context) error, interval time.Duration) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := apply(ctx); err == nil {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
