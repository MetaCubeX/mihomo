package observable

import (
	"errors"
	"sync"
)

type Observable struct {
	iterable Iterable
	listener *sync.Map
	done     bool
	doneLock sync.RWMutex
}

func (o *Observable) process() {
	for item := range o.iterable {
		o.listener.Range(func(key, value interface{}) bool {
			elm := value.(*Subscriber)
			elm.Emit(item)
			return true
		})
	}
	o.close()
}

func (o *Observable) close() {
	o.doneLock.Lock()
	o.done = true
	o.doneLock.Unlock()

	o.listener.Range(func(key, value interface{}) bool {
		elm := value.(*Subscriber)
		elm.Close()
		return true
	})
}

func (o *Observable) Subscribe() (Subscription, error) {
	o.doneLock.RLock()
	done := o.done
	o.doneLock.RUnlock()
	if done == true {
		return nil, errors.New("Observable is closed")
	}
	subscriber := newSubscriber()
	o.listener.Store(subscriber.Out(), subscriber)
	return subscriber.Out(), nil
}

func (o *Observable) UnSubscribe(sub Subscription) {
	elm, exist := o.listener.Load(sub)
	if !exist {
		println("not exist")
		return
	}
	subscriber := elm.(*Subscriber)
	o.listener.Delete(subscriber.Out())
	subscriber.Close()
}

func NewObservable(any Iterable) *Observable {
	observable := &Observable{
		iterable: any,
		listener: &sync.Map{},
	}
	go observable.process()
	return observable
}
