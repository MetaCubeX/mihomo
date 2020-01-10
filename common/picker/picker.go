package picker

import (
	"context"
	"sync"
	"time"
)

// Picker provides synchronization, and Context cancelation
// for groups of goroutines working on subtasks of a common task.
// Inspired by errGroup
type Picker struct {
	ctx    context.Context
	cancel func()

	wg sync.WaitGroup

	once   sync.Once
	result interface{}

	firstDone chan struct{}
}

func newPicker(ctx context.Context, cancel func()) *Picker {
	return &Picker{
		ctx:       ctx,
		cancel:    cancel,
		firstDone: make(chan struct{}, 1),
	}
}

// WithContext returns a new Picker and an associated Context derived from ctx.
// and cancel when first element return.
func WithContext(ctx context.Context) (*Picker, context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	return newPicker(ctx, cancel), ctx
}

// WithTimeout returns a new Picker and an associated Context derived from ctx with timeout.
func WithTimeout(ctx context.Context, timeout time.Duration) (*Picker, context.Context) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	return newPicker(ctx, cancel), ctx
}

// WithoutAutoCancel returns a new Picker and an associated Context derived from ctx,
// but it wouldn't cancel context when the first element return.
func WithoutAutoCancel(ctx context.Context) *Picker {
	return newPicker(ctx, nil)
}

// Wait blocks until all function calls from the Go method have returned,
// then returns the first nil error result (if any) from them.
func (p *Picker) Wait() interface{} {
	p.wg.Wait()
	if p.cancel != nil {
		p.cancel()
	}
	return p.result
}

// WaitWithoutCancel blocks until the first result return, if timeout will return nil.
// The return of this function will not wait for the cancel of context.
func (p *Picker) WaitWithoutCancel() interface{} {
	select {
	case <-p.firstDone:
		return p.result
	case <-p.ctx.Done():
		return p.result
	}
}

// Go calls the given function in a new goroutine.
// The first call to return a nil error cancels the group; its result will be returned by Wait.
func (p *Picker) Go(f func() (interface{}, error)) {
	p.wg.Add(1)

	go func() {
		defer p.wg.Done()

		if ret, err := f(); err == nil {
			p.once.Do(func() {
				p.result = ret
				p.firstDone <- struct{}{}
				if p.cancel != nil {
					p.cancel()
				}
			})
		}
	}()
}
