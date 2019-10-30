package observable

import (
	"errors"
	"sync"
)

type Observable struct {
	iterable Iterable
	listener map[Subscription]*Subscriber
	mux      sync.Mutex
	done     bool
}

func (o *Observable) process() {
	for item := range o.iterable {
		o.mux.Lock()
		for _, sub := range o.listener {
			sub.Emit(item)
		}
		o.mux.Unlock()
	}
	o.close()
}

func (o *Observable) close() {
	o.mux.Lock()
	defer o.mux.Unlock()

	o.done = true
	for _, sub := range o.listener {
		sub.Close()
	}
}

func (o *Observable) Subscribe() (Subscription, error) {
	o.mux.Lock()
	defer o.mux.Unlock()
	if o.done {
		return nil, errors.New("Observable is closed")
	}
	subscriber := newSubscriber()
	o.listener[subscriber.Out()] = subscriber
	return subscriber.Out(), nil
}

func (o *Observable) UnSubscribe(sub Subscription) {
	o.mux.Lock()
	defer o.mux.Unlock()
	subscriber, exist := o.listener[sub]
	if !exist {
		return
	}
	delete(o.listener, sub)
	subscriber.Close()
}

func NewObservable(any Iterable) *Observable {
	observable := &Observable{
		iterable: any,
		listener: map[Subscription]*Subscriber{},
	}
	go observable.process()
	return observable
}
