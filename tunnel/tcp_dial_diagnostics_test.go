package tunnel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTCPDialDiagnosticError(t *testing.T) {
	started := time.Now()
	err := tcpDialDiagnosticError(context.DeadlineExceeded, 2, started, started.Add(-time.Second), 15*time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("diagnostics lost the original deadline error")
	}
	for _, field := range []string{"attempt=2", "attempt_elapsed=", "total_elapsed=", "budget=15s", "context deadline exceeded"} {
		if !strings.Contains(err.Error(), field) {
			t.Fatalf("missing diagnostic %q: %v", field, err)
		}
	}
}
