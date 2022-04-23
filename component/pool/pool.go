package pool

import (
	"context"
	"runtime"
	"time"
)

type Factory[T any] func(context.Context) (T, error)

type entry[T any] struct {
	elm  T
	time time.Time
}

type Option[T any] func(*pool[T])

// WithEvict set the evict callback
func WithEvict[T any](cb func(T)) Option[T] {
	return func(p *pool[T]) {
		p.evict = cb
	}
}

// WithAge defined element max age (millisecond)
func WithAge[T any](maxAge int64) Option[T] {
	return func(p *pool[T]) {
		p.maxAge = maxAge
	}
}

// WithSize defined max size of Pool
func WithSize[T any](maxSize int) Option[T] {
	return func(p *pool[T]) {
		p.ch = make(chan *entry[T], maxSize)
	}
}

// Pool is for GC, see New for detail
type Pool[T any] struct {
	*pool[T]
}

type pool[T any] struct {
	ch      chan *entry[T]
	factory Factory[T]
	evict   func(T)
	maxAge  int64
}

func (p *pool[T]) GetContext(ctx context.Context) (T, error) {
	now := time.Now()
	for {
		select {
		case item := <-p.ch:
			elm := item
			if p.maxAge != 0 && now.Sub(item.time).Milliseconds() > p.maxAge {
				if p.evict != nil {
					p.evict(elm.elm)
				}
				continue
			}

			return elm.elm, nil
		default:
			return p.factory(ctx)
		}
	}
}

func (p *pool[T]) Get() (T, error) {
	return p.GetContext(context.Background())
}

func (p *pool[T]) Put(item T) {
	e := &entry[T]{
		elm:  item,
		time: time.Now(),
	}

	select {
	case p.ch <- e:
		return
	default:
		// pool is full
		if p.evict != nil {
			p.evict(item)
		}
		return
	}
}

func recycle[T any](p *Pool[T]) {
	for item := range p.pool.ch {
		if p.pool.evict != nil {
			p.pool.evict(item.elm)
		}
	}
}

func New[T any](factory Factory[T], options ...Option[T]) *Pool[T] {
	p := &pool[T]{
		ch:      make(chan *entry[T], 10),
		factory: factory,
	}

	for _, option := range options {
		option(p)
	}

	P := &Pool[T]{p}
	runtime.SetFinalizer(P, recycle[T])
	return P
}
