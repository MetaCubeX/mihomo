package executor

import (
	"testing"

	"github.com/metacubex/mihomo/config"
)

func TestTCPHalfCloseTimeoutApplyAndRestore(t *testing.T) {
	previous := GetGeneral()
	t.Cleanup(func() { updateGeneral(previous, false) })
	next := *previous
	next.TCPHalfCloseTimeout = config.TCPHalfCloseTimeout{Client: 300, Server: 30}
	restore := temporaryUpdateGeneral(&next)
	if got := GetGeneral().TCPHalfCloseTimeout; got != next.TCPHalfCloseTimeout {
		t.Fatalf("applied timeout = %+v, want %+v", got, next.TCPHalfCloseTimeout)
	}
	restore()
	if got := GetGeneral().TCPHalfCloseTimeout; got != previous.TCPHalfCloseTimeout {
		t.Fatalf("restored timeout = %+v, want %+v", got, previous.TCPHalfCloseTimeout)
	}
	next.TCPHalfCloseTimeout = config.TCPHalfCloseTimeout{}
	updateGeneral(&next, false)
	if got := GetGeneral().TCPHalfCloseTimeout; got != (config.TCPHalfCloseTimeout{}) {
		t.Fatalf("failed to disable timeout: %+v", got)
	}
}
