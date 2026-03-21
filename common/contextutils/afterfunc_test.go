package contextutils

import (
	"context"
	"testing"
	"time"
)

const (
	shortDuration    = 1 * time.Millisecond // a reasonable duration to block in a test
	veryLongDuration = 1000 * time.Hour     // an arbitrary upper bound on the test's running time
)

func TestAfterFuncCalledAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	donec := make(chan struct{})
	stop := afterFunc(ctx, func() {
		close(donec)
	})
	select {
	case <-donec:
		t.Fatalf("AfterFunc called before context is done")
	case <-time.After(shortDuration):
	}
	cancel()
	select {
	case <-donec:
	case <-time.After(veryLongDuration):
		t.Fatalf("AfterFunc not called after context is canceled")
	}
	if stop() {
		t.Fatalf("stop() = true, want false")
	}
}

func TestAfterFuncCalledAfterTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), shortDuration)
	defer cancel()
	donec := make(chan struct{})
	afterFunc(ctx, func() {
		close(donec)
	})
	select {
	case <-donec:
	case <-time.After(veryLongDuration):
		t.Fatalf("AfterFunc not called after context is canceled")
	}
}

func TestAfterFuncCalledImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	donec := make(chan struct{})
	afterFunc(ctx, func() {
		close(donec)
	})
	select {
	case <-donec:
	case <-time.After(veryLongDuration):
		t.Fatalf("AfterFunc not called for already-canceled context")
	}
}

func TestAfterFuncNotCalledAfterStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	donec := make(chan struct{})
	stop := afterFunc(ctx, func() {
		close(donec)
	})
	if !stop() {
		t.Fatalf("stop() = false, want true")
	}
	cancel()
	select {
	case <-donec:
		t.Fatalf("AfterFunc called for already-canceled context")
	case <-time.After(shortDuration):
	}
	if stop() {
		t.Fatalf("stop() = true, want false")
	}
}

// This test verifies that canceling a context does not block waiting for AfterFuncs to finish.
func TestAfterFuncCalledAsynchronously(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	donec := make(chan struct{})
	stop := afterFunc(ctx, func() {
		// The channel send blocks until donec is read from.
		donec <- struct{}{}
	})
	defer stop()
	cancel()
	// After cancel returns, read from donec and unblock the AfterFunc.
	select {
	case <-donec:
	case <-time.After(veryLongDuration):
		t.Fatalf("AfterFunc not called after context is canceled")
	}
}
