package observable

import (
	"errors"
	"sync"
)

type Observable[T any] struct {
	iterable Iterable[T]
	listener map[Subscription[T]]*Subscriber[T]
	mux      sync.Mutex
	done     bool
}

func (o *Observable[T]) process() {
	for item := range o.iterable {
		o.mux.Lock()
		for _, sub := range o.listener {
			sub.Emit(item)
		}
		o.mux.Unlock()
	}
	o.close()
}

func (o *Observable[T]) close() {
	o.mux.Lock()
	defer o.mux.Unlock()

	o.done = true
	for _, sub := range o.listener {
		sub.Close()
	}
}

func (o *Observable[T]) Subscribe() (Subscription[T], error) {
	o.mux.Lock()
	defer o.mux.Unlock()
	if o.done {
		return nil, errors.New("observable is closed")
	}
	subscriber := newSubscriber[T]()
	o.listener[subscriber.Out()] = subscriber
	return subscriber.Out(), nil
}

func (o *Observable[T]) UnSubscribe(sub Subscription[T]) {
	o.mux.Lock()
	defer o.mux.Unlock()
	subscriber, exist := o.listener[sub]
	if !exist {
		return
	}
	delete(o.listener, sub)
	subscriber.Close()
}

func NewObservable[T any](iter Iterable[T]) *Observable[T] {
	observable := &Observable[T]{
		iterable: iter,
		listener: map[Subscription[T]]*Subscriber[T]{},
	}
	go observable.process()
	return observable
}
