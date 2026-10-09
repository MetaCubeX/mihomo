package tunnel

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestTCPConnectTimeoutValidation(t *testing.T) {
	old := TCPConnectTimeout().Milliseconds()
	t.Cleanup(func() { _ = SetTCPConnectTimeout(old) })
	for _, value := range []int64{0, -1, math.MaxInt64} {
		if err := SetTCPConnectTimeout(value); err == nil {
			t.Fatalf("accepted invalid timeout %d", value)
		}
		if TCPConnectTimeout().Milliseconds() != old {
			t.Fatal("invalid timeout changed runtime state")
		}
	}
}

func TestTCPConnectContext(t *testing.T) {
	old := TCPConnectTimeout().Milliseconds()
	t.Cleanup(func() { _ = SetTCPConnectTimeout(old) })
	if TCPConnectTimeout() != C.DefaultTCPTimeout {
		t.Fatal("default must preserve the existing TCP budget")
	}
	_ = SetTCPConnectTimeout(15000)
	start := time.Now()
	ctx, cancel := tcpConnectContext(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Before(start.Add(15*time.Second)) || deadline.After(time.Now().Add(15*time.Second)) {
		t.Fatalf("unexpected configured deadline: %v", deadline)
	}
	_ = SetTCPConnectTimeout(20)
	if current, _ := ctx.Deadline(); !current.Equal(deadline) {
		t.Fatal("runtime update changed an existing connection budget")
	}
	short, stop := tcpConnectContext(context.Background())
	defer stop()
	_, err := retry(short, func(ctx context.Context) (struct{}, error) {
		<-ctx.Done()
		return struct{}{}, ctx.Err()
	}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected connection deadline, got %v", err)
	}
	parent, stopParent := context.WithCancel(context.Background())
	child, stopChild := tcpConnectContext(parent)
	defer stopChild()
	stopParent()
	if !errors.Is(child.Err(), context.Canceled) {
		t.Fatal("caller cancellation was not preserved")
	}
	if C.DefaultUDPTimeout != 5*time.Second || C.DefaultTLSTimeout != 5*time.Second {
		t.Fatal("unrelated default timeouts changed")
	}
}
