//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryTailscaleExitNodeWaitsForPeer(t *testing.T) {
	calls := 0
	err := retryTailscaleExitNode(context.Background(), func(context.Context) error {
		calls++
		if calls < 3 {
			return errors.New("no node found in netmap")
		}
		return nil
	}, time.Millisecond)
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestRetryTailscaleExitNodeFailsClosedAtDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	err := retryTailscaleExitNode(ctx, func(context.Context) error {
		return errors.New("no node found in netmap")
	}, time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRetryTailscaleExitNodeDoesNotApplyAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := retryTailscaleExitNode(ctx, func(context.Context) error { calls++; return nil }, time.Millisecond)
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
