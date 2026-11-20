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
	if leftToRightEOFTimeout <= 0 && rightToLeftEOFTimeout <= 0 {
		Relay(left, right)
		return
	}
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}
	defer closeBoth()

	activity := &relayActivity{start: time.Now()}
	var mu sync.Mutex
	var timer *time.Timer
	var completed int
	finish := func(timeout time.Duration, err error) {
		if err != nil {
			closeBoth()
		}
		mu.Lock()
		defer mu.Unlock()
		completed++
		if completed == 2 {
			if timer != nil {
				timer.Stop()
			}
			return
		}
		if err != nil || timeout <= 0 {
			return
		}

		// Start the allowance at EOF; fully open transfers need no per-write clock reads.
		halfClosedAt := time.Since(activity.start)
		activity.enabled.Store(true)
		timer = time.AfterFunc(timeout, func() {
			mu.Lock()
			if completed == 2 {
				mu.Unlock()
				return
			}
			last := time.Duration(activity.last.Load())
			if last < halfClosedAt {
				last = halfClosedAt
			}
			idle := time.Since(activity.start) - last
			if idle < timeout {
				timer.Reset(timeout - idle)
				mu.Unlock()
				return
			}
			mu.Unlock()
			// Logical Close also interrupts a copy blocked in Write.
			closeBoth()
		})
	}
	copyDirection := func(dst, src net.Conn, timeout time.Duration) {
		_, err := bufio.Copy(&relayActivityWriter{Writer: dst, activity: activity}, src)
		if err == nil {
			err = closeWrite(dst)
		}
		finish(timeout, err)
	}
	// Keep the same one-worker topology as Relay. A timer is created only
	// after a successful half-close, and both copies are joined before return.
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyDirection(left, right, rightToLeftEOFTimeout)
	}()
	copyDirection(right, left, leftToRightEOFTimeout)
	<-done
}

type relayActivity struct {
	start   time.Time
	last    atomic.Int64
	enabled atomic.Bool
}

type relayActivityWriter struct {
	io.Writer
	activity *relayActivity
}

// Use sing's counting interface so cached reads, optimized copies and existing
// traffic counters continue to work. Updating a timestamp needs no per-write timer.
func (w *relayActivityWriter) UnwrapWriter() (io.Writer, []CountFunc) {
	return w.Writer, []CountFunc{func(n int64) {
		if n > 0 && w.activity.enabled.Load() {
			w.activity.last.Store(time.Since(w.activity.start).Nanoseconds())
		}
	}}
}
