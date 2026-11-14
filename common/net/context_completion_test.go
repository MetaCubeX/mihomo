//go:build go1.25

package net_test

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"testing/synctest"

	N "github.com/metacubex/mihomo/common/net"
)

type completionConn struct {
	net.Conn
	gate   <-chan struct{}
	closed int
}

func (c *completionConn) Close() error {
	c.closed++
	if c.gate != nil {
		<-c.gate
	}
	return nil
}

func TestSetupContextCompletionStopped(t *testing.T) {
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",asynctimerchan=0")
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := &completionConn{}
		done := N.SetupContextForConn(ctx, c)
		expected := errors.New("write failure")
		err := expected
		done(&err)
		cancel()
		synctest.Wait()
		if c.closed != 0 || err != expected {
			t.Fatalf("closed=%d err=%v", c.closed, err)
		}
	})
}
func TestSetupContextCompletionWaits(t *testing.T) {
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",asynctimerchan=0")
	for _, alreadyCanceled := range []bool{false, true} {
		name := "cancel-after-register"
		if alreadyCanceled {
			name = "already-canceled"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if alreadyCanceled {
					cancel()
				}
				gate := make(chan struct{})
				defer func() {
					select {
					case <-gate:
					default:
						close(gate)
					}
				}()
				c := &completionConn{gate: gate}
				done := N.SetupContextForConn(ctx, c)
				cancel()
				synctest.Wait()
				var err error
				returned := false
				go func() { done(&err); returned = true }()
				synctest.Wait()
				if returned || c.closed != 1 {
					t.Fatalf("returned=%v closed=%d", returned, c.closed)
				}
				close(gate)
				synctest.Wait()
				if !returned || !errors.Is(err, context.Canceled) {
					t.Fatalf("returned=%v err=%v", returned, err)
				}
			})
		})
	}
}
func TestSetupContextCompletionNilError(t *testing.T) {
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",asynctimerchan=0")
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		c := &completionConn{}
		done := N.SetupContextForConn(ctx, c)
		cancel()
		done(nil)
		if c.closed != 1 {
			t.Fatalf("closed=%d", c.closed)
		}
	})
}
func TestSetupContextCompletionBackground(t *testing.T) {
	c := &completionConn{}
	done := N.SetupContextForConn(context.Background(), c)
	done(nil)
	if c.closed != 0 {
		t.Fatalf("closed=%d", c.closed)
	}
}
func TestSetupContextCompletionRace(t *testing.T) {
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",asynctimerchan=0")
	for i := 0; i < 100; i++ {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := &completionConn{}
			done := N.SetupContextForConn(ctx, c)
			var err error
			go cancel()
			go func() { done(&err) }()
			synctest.Wait()
			if c.closed > 1 || c.closed == 1 && !errors.Is(err, context.Canceled) || c.closed == 0 && err != nil {
				t.Fatalf("closed=%d err=%v", c.closed, err)
			}
		})
	}
}
