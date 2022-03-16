package observable

import (
	"sync"
)

type Subscription <-chan any

type Subscriber struct {
	buffer chan any
	once   sync.Once
}

func (s *Subscriber) Emit(item any) {
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
		buffer: make(chan any, 200),
	}
	return sub
}
