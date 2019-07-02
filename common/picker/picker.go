package picker

import (
	"context"
	"sync"
)

// Picker provides synchronization, and Context cancelation
// for groups of goroutines working on subtasks of a common task.
// Inspired by errGroup
type Picker struct {
	cancel func()

	wg sync.WaitGroup

	once   sync.Once
	result interface{}
}

// WithContext returns a new Picker and an associated Context derived from ctx.
func WithContext(ctx context.Context) (*Picker, context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	return &Picker{cancel: cancel}, ctx
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

// Go calls the given function in a new goroutine.
// The first call to return a nil error cancels the group; its result will be returned by Wait.
func (p *Picker) Go(f func() (interface{}, error)) {
	p.wg.Add(1)

	go func() {
		defer p.wg.Done()

		if ret, err := f(); err == nil {
			p.once.Do(func() {
				p.result = ret
				if p.cancel != nil {
					p.cancel()
				}
			})
		}
	}()
}
