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
	installed        atomic.Bool
	allowCount       atomic.Int64
	blockReportCount atomic.Int64
)

// Install protects against accidental net.DefaultResolver usage. Unapproved
// lookups fail closed instead of exiting the process; this keeps background
// library DNS mistakes from crashing the daemon.
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

		reportBlockedDefaultResolver(network, address)
		return nil, fmt.Errorf("net.DefaultResolver lookup blocked; use mihomo resolver or defaultguard.Allow (network=%s address=%s)", network, address)
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

func reportBlockedDefaultResolver(network, address string) {
	count := blockReportCount.Add(1)
	if !shouldReportBlockedDefaultResolver(count) {
		return
	}
	fmt.Fprintf(os.Stderr, "net.DefaultResolver lookup blocked count=%d network=%s address=%s\n\n%s", count, network, address, resolverGuardStack())
}

func shouldReportBlockedDefaultResolver(count int64) bool {
	return count <= 3 || count == 10 || count == 100 || count%1000 == 0
}

func resolverGuardStack() []byte {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, false)
		if n < len(buf) {
			return buf[:n]
		}
		buf = make([]byte, 2*len(buf))
	}
}
