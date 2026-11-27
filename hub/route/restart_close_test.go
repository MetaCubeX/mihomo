//go:build !windows

package route

import (
	"errors"
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

type closeRecordingProxy struct {
	C.Proxy
	closes atomic.Int32
}

func (p *closeRecordingProxy) Close() error {
	p.closes.Add(1)
	return nil
}

type failingCloseProxy struct {
	C.Proxy
	closes atomic.Int32
}

func (p *failingCloseProxy) Close() error {
	p.closes.Add(1)
	return errors.New("close failed")
}

func TestRestartClosesOutboundsBeforeExec(t *testing.T) {
	good := &closeRecordingProxy{}
	bad := &failingCloseProxy{}
	tunnel.UpdateProxies(map[string]C.Proxy{"good": good, "bad": bad}, nil)
	t.Cleanup(func() { tunnel.UpdateProxies(map[string]C.Proxy{}, nil) })

	oldExec := execRestart
	defer func() { execRestart = oldExec }()
	execCalled := false
	execRestart = func(string, []string, []string) error {
		execCalled = true
		if got := good.closes.Load(); got != 1 {
			t.Errorf("good proxy Close calls before exec = %d, want 1", got)
		}
		if got := bad.closes.Load(); got != 1 {
			t.Errorf("failing proxy Close calls before exec = %d, want 1", got)
		}
		return nil
	}

	restartExecutable("/bin/true")
	if !execCalled {
		t.Fatal("restart did not reach exec")
	}
	if got := good.closes.Load(); got != 1 {
		t.Fatalf("good proxy Close calls = %d, want exactly 1", got)
	}
	if got := bad.closes.Load(); got != 1 {
		t.Fatalf("failing proxy Close calls = %d, want exactly 1", got)
	}
}
