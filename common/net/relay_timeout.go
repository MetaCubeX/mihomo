package net

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/sing/common/bufio"
)

// RelayWithHalfCloseTimeout relays both directions, preserving TCP half-close.
// leftToRightEOFTimeout is the idle allowance for the remaining direction after
// left -> right finishes; rightToLeftEOFTimeout applies after right -> left ends.
// A non-positive allowance disables idle cleanup for that half-close direction.
// Fully open connections have no idle timeout here.
func RelayWithHalfCloseTimeout(left, right net.Conn, leftToRightEOFTimeout, rightToLeftEOFTimeout time.Duration) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}
	defer closeBoth()

	activity := &relayActivity{start: time.Now()}
	type result struct {
		leftToRight bool
		err         error
	}
	finished := make(chan result, 2)
	copyDirection := func(dst, src net.Conn, leftToRight bool) {
		_, err := bufio.Copy(&relayActivityWriter{Writer: dst, activity: activity}, src)
		if err == nil {
			err = closeWrite(dst)
		}
		finished <- result{leftToRight: leftToRight, err: err}
	}
	go copyDirection(right, left, true)
	go copyDirection(left, right, false)

	first := <-finished
	if first.err != nil {
		closeBoth()
		<-finished // Join the other copy before releasing connection references.
		return
	}

	timeout := rightToLeftEOFTimeout
	if first.leftToRight {
		timeout = leftToRightEOFTimeout
	}
	if timeout <= 0 {
		<-finished
		return
	}

	// Give the peer a full allowance starting at half-close, even if the last
	// payload was forwarded long ago. Use a monotonic clock throughout.
	halfClosedAt := time.Since(activity.start)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-finished:
			return
		case <-timer.C:
			last := time.Duration(activity.last.Load())
			if last < halfClosedAt {
				last = halfClosedAt
			}
			idle := time.Since(activity.start) - last
			if idle >= timeout {
				// Close the logical connections, rather than relying on adapter
				// read deadlines: the other copy may also be blocked in Write.
				closeBoth()
				<-finished
				return
			}
			timer.Reset(timeout - idle)
		}
	}
}

type relayActivity struct {
	start time.Time
	last  atomic.Int64
}

type relayActivityWriter struct {
	io.Writer
	activity *relayActivity
}

// Use sing's counting interface so cached reads, optimized copies and existing
// traffic counters continue to work. Updating a timestamp needs no per-write timer.
func (w *relayActivityWriter) UnwrapWriter() (io.Writer, []CountFunc) {
	return w.Writer, []CountFunc{func(n int64) {
		if n > 0 {
			w.activity.last.Store(time.Since(w.activity.start).Nanoseconds())
		}
	}}
}
