package defaultguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
)

var (
	installed  atomic.Bool
	allowCount atomic.Int64
)

// Install protects against accidental net.DefaultResolver usage.
func Install() {
	if installed.Swap(true) {
		return
	}

	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if allowCount.Load() > 0 {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		}

		fmt.Fprintf(os.Stderr, "panic: should never be called\n\n%s", resolverGuardStack()) // always print all goroutine stack
		os.Exit(2)
		return nil, nil
	}
}

// Allow temporarily permits libraries that cannot inject a resolver to use the
// process default resolver. Callers must keep the returned release function
// scoped to the exact operation that needs the escape hatch.
func Allow() func() {
	allowCount.Add(1)
	var released atomic.Bool
	return func() {
		if released.CompareAndSwap(false, true) {
			allowCount.Add(-1)
		}
	}
}

func resolverGuardStack() []byte {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return buf[:n]
		}
		buf = make([]byte, 2*len(buf))
	}
}
