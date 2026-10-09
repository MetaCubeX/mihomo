package tunnel

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
)

type namedRetryError struct {
	name string
	err  error
}

func TestShouldStopRetryLocalResourceExhaustion(t *testing.T) {
	for _, test := range localResourceExhaustionTestCases() {
		t.Run(test.name+"/direct", func(t *testing.T) {
			if !shouldStopRetry(test.err) {
				t.Fatal("shouldStopRetry() = false, want true")
			}
		})

		t.Run(test.name+"/wrapped", func(t *testing.T) {
			err := &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "connect", Err: test.err},
			}
			if !shouldStopRetry(err) {
				t.Fatal("shouldStopRetry() = false, want true")
			}
		})
	}
}

func TestRetryStopsOnLocalResourceExhaustion(t *testing.T) {
	resourceErr := localResourceExhaustionTestCases()[0].err
	attempts := 0
	_, err := retry(context.Background(), func(context.Context) (struct{}, error) {
		attempts++
		return struct{}{}, resourceErr
	}, nil)
	if !errors.Is(err, resourceErr) {
		t.Fatalf("retry() error = %v, want %v", err, resourceErr)
	}
	if attempts != 1 {
		t.Fatalf("retry() attempts = %d, want 1", attempts)
	}
}

func TestRetryPreservesTransientErrorBehavior(t *testing.T) {
	transientErr := errors.New("transient network error")
	attempts := 0
	result, err := retry(context.Background(), func(context.Context) (string, error) {
		attempts++
		if attempts == 1 {
			return "", transientErr
		}
		return "connected", nil
	}, nil)
	if err != nil {
		t.Fatalf("retry() error = %v, want nil", err)
	}
	if result != "connected" {
		t.Fatalf("retry() result = %q, want connected", result)
	}
	if attempts != 2 {
		t.Fatalf("retry() attempts = %d, want 2", attempts)
	}
}
