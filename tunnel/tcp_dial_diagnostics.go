package tunnel

import (
	"fmt"
	"time"
)

// tcpDialDiagnosticError adds timings without discarding the original cause.
func tcpDialDiagnosticError(err error, attempt int, attemptStarted, dialStarted time.Time, budget time.Duration) error {
	now := time.Now()
	return fmt.Errorf("attempt=%d attempt_elapsed=%s total_elapsed=%s budget=%s: %w",
		attempt, now.Sub(attemptStarted).Round(time.Millisecond), now.Sub(dialStarted).Round(time.Millisecond), budget.Round(time.Millisecond), err)
}
