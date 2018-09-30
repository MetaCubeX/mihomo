package observable

import (
	"sync"

	"gopkg.in/eapache/channels.v1"
)

type Subscription <-chan interface{}

type Subscriber struct {
	buffer *channels.InfiniteChannel
	once   sync.Once
}

func (s *Subscriber) Emit(item interface{}) {
	s.buffer.In() <- item
}

func (s *Subscriber) Out() Subscription {
	return s.buffer.Out()
}

func (s *Subscriber) Close() {
	s.once.Do(func() {
		s.buffer.Close()
	})
}

func newSubscriber() *Subscriber {
	sub := &Subscriber{
		buffer: channels.NewInfiniteChannel(),
	}
	return sub
}
