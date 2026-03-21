package slowdown

import (
	"context"
	"sync/atomic"
	"time"
)

type SlowDown struct {
	errTimes atomic.Int64
	backoff  Backoff
}

func (s *SlowDown) Wait(ctx context.Context) (err error) {
	timer := time.NewTimer(s.backoff.Duration())
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		err = ctx.Err()
	}
	return
}

func New() *SlowDown {
	return &SlowDown{
		backoff: Backoff{
			Min:    10 * time.Millisecond,
			Max:    1 * time.Second,
			Factor: 2,
			Jitter: true,
		},
	}
}

func Do[T any](s *SlowDown, ctx context.Context, fn func() (T, error)) (t T, err error) {
	if s.errTimes.Load() > 10 {
		err = s.Wait(ctx)
		if err != nil {
			return
		}
	}
	t, err = fn()
	if err != nil {
		s.errTimes.Add(1)
		return
	}
	s.errTimes.Store(0)
	s.backoff.Reset()
	return
}
