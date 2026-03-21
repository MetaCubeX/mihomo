package contextutils

import (
	"context"
	"sync"
)

func afterFunc(ctx context.Context, f func()) (stop func() bool) {
	stopc := make(chan struct{})
	once := sync.Once{} // either starts running f or stops f from running
	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				once.Do(func() {
					go f()
				})
			case <-stopc:
			}
		}()
	}

	return func() bool {
		stopped := false
		once.Do(func() {
			stopped = true
			close(stopc)
		})
		return stopped
	}
}
