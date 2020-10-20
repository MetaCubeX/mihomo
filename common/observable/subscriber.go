package observable

import (
	"sync"
)

type Subscription <-chan interface{}

type Subscriber struct {
	buffer chan interface{}
	once   sync.Once
}

func (s *Subscriber) Emit(item interface{}) {
	s.buffer <- item
}

func (s *Subscriber) Out() Subscription {
	return s.buffer
}

func (s *Subscriber) Close() {
	s.once.Do(func() {
		close(s.buffer)
	})
}

func newSubscriber() *Subscriber {
	sub := &Subscriber{
		buffer: make(chan interface{}, 200),
	}
	return sub
}
