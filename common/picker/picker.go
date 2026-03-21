package picker

import (
	"context"
	"sync"
	"time"
)

// Picker provides synchronization, and Context cancelation
// for groups of goroutines working on subtasks of a common task.
// Inspired by errGroup
type Picker[T any] struct {
	ctx    context.Context
	cancel func()

	wg sync.WaitGroup

	once    sync.Once
	errOnce sync.Once
	result  T
	err     error
}

func newPicker[T any](ctx context.Context, cancel func()) *Picker[T] {
	return &Picker[T]{
		ctx:    ctx,
		cancel: cancel,
	}
}

// WithContext returns a new Picker and an associated Context derived from ctx.
// and cancel when first element return.
func WithContext[T any](ctx context.Context) (*Picker[T], context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	return newPicker[T](ctx, cancel), ctx
}

// WithTimeout returns a new Picker and an associated Context derived from ctx with timeout.
func WithTimeout[T any](ctx context.Context, timeout time.Duration) (*Picker[T], context.Context) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	return newPicker[T](ctx, cancel), ctx
}

// Wait blocks until all function calls from the Go method have returned,
// then returns the first nil error result (if any) from them.
func (p *Picker[T]) Wait() T {
	p.wg.Wait()
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	return p.result
}

// Error return the first error (if all success return nil)
func (p *Picker[T]) Error() error {
	return p.err
}

// Go calls the given function in a new goroutine.
// The first call to return a nil error cancels the group; its result will be returned by Wait.
func (p *Picker[T]) Go(f func() (T, error)) {
	p.wg.Add(1)

	go func() {
		defer p.wg.Done()

		if ret, err := f(); err == nil {
			p.once.Do(func() {
				p.result = ret
				if p.cancel != nil {
					p.cancel()
					p.cancel = nil
				}
			})
		} else {
			p.errOnce.Do(func() {
				p.err = err
			})
		}
	}()
}

// Close cancels the picker context and releases resources associated with it.
// If Wait has been called, then there is no need to call Close.
func (p *Picker[T]) Close() error {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	return nil
}
