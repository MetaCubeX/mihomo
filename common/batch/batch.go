package batch

import (
	"context"
	"sync"
)

type Option = func(b *Batch)

type Result struct {
	Value any
	Err   error
}

type Error struct {
	Key string
	Err error
}

func WithConcurrencyNum(n int) Option {
	return func(b *Batch) {
		q := make(chan struct{}, n)
		for i := 0; i < n; i++ {
			q <- struct{}{}
		}
		b.queue = q
	}
}

// Batch similar to errgroup, but can control the maximum number of concurrent
type Batch struct {
	result map[string]Result
	queue  chan struct{}
	wg     sync.WaitGroup
	mux    sync.Mutex
	err    *Error
	once   sync.Once
	cancel func()
}

func (b *Batch) Go(key string, fn func() (any, error)) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		if b.queue != nil {
			<-b.queue
			defer func() {
				b.queue <- struct{}{}
			}()
		}

		value, err := fn()
		if err != nil {
			b.once.Do(func() {
				b.err = &Error{key, err}
				if b.cancel != nil {
					b.cancel()
				}
			})
		}

		ret := Result{value, err}
		b.mux.Lock()
		defer b.mux.Unlock()
		b.result[key] = ret
	}()
}

func (b *Batch) Wait() *Error {
	b.wg.Wait()
	if b.cancel != nil {
		b.cancel()
	}
	return b.err
}

func (b *Batch) WaitAndGetResult() (map[string]Result, *Error) {
	err := b.Wait()
	return b.Result(), err
}

func (b *Batch) Result() map[string]Result {
	b.mux.Lock()
	defer b.mux.Unlock()
	copy := map[string]Result{}
	for k, v := range b.result {
		copy[k] = v
	}
	return copy
}

func New(ctx context.Context, opts ...Option) (*Batch, context.Context) {
	ctx, cancel := context.WithCancel(ctx)

	b := &Batch{
		result: map[string]Result{},
	}

	for _, o := range opts {
		o(b)
	}

	b.cancel = cancel
	return b, ctx
}
