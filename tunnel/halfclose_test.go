package tunnel

import (
	"testing"
	"time"
)

func TestTCPHalfCloseTimeoutSnapshot(t *testing.T) {
	previous := halfCloseTimeout.Load()
	t.Cleanup(func() { halfCloseTimeout.Store(previous) })
	halfCloseTimeout.Store(nil)
	client, server := TCPHalfCloseTimeout()
	if client != 0 || server != 0 {
		t.Fatal("cleanup must be disabled by default")
	}
	SetTCPHalfCloseTimeout(5*time.Minute, 30*time.Second)
	snapshot := halfCloseTimeout.Load()
	SetTCPHalfCloseTimeout(0, 0)
	client, server = TCPHalfCloseTimeout()
	if client != 0 || server != 0 || snapshot.client != 5*time.Minute || snapshot.server != 30*time.Second {
		t.Fatal("reload must replace the policy without mutating an existing snapshot")
	}
}
