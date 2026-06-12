package outbound

import (
	"context"
	"testing"
	"time"
)

func TestOpenVPNHandshakeContextFollowsCallerCancellation(t *testing.T) {
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	outbound := &OpenVPN{runCtx: runCtx}
	parent, parentCancel := context.WithCancel(context.Background())
	handshakeCtx, cancel := outbound.handshakeContext(parent)
	defer cancel()

	parentCancel()

	select {
	case <-handshakeCtx.Done():
		if handshakeCtx.Err() != context.Canceled {
			t.Fatalf("unexpected handshake context error: %v", handshakeCtx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("expected handshake context to follow caller cancellation")
	}
}

func TestOpenVPNHandshakeContextFollowsRunContextCancellation(t *testing.T) {
	runCtx, runCancel := context.WithCancel(context.Background())
	outbound := &OpenVPN{runCtx: runCtx}
	handshakeCtx, cancel := outbound.handshakeContext(context.Background())
	defer cancel()

	runCancel()

	select {
	case <-handshakeCtx.Done():
		if handshakeCtx.Err() != context.Canceled {
			t.Fatalf("unexpected handshake context error: %v", handshakeCtx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("expected handshake context to follow run context cancellation")
	}
}
