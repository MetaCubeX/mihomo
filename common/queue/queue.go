package queue

import (
	"sync"
)

// Queue is a simple concurrent safe queue
type Queue[T any] struct {
	items []T
	lock  sync.RWMutex
}

// Put add the item to the queue.
func (q *Queue[T]) Put(items ...T) {
	if len(items) == 0 {
		return
	}

	q.lock.Lock()
	q.items = append(q.items, items...)
	q.lock.Unlock()
}

// Pop returns the head of items.
func (q *Queue[T]) Pop() T {
	if len(q.items) == 0 {
		return GetZero[T]()
	}

	q.lock.Lock()
	head := q.items[0]
	q.items = q.items[1:]
	q.lock.Unlock()
	return head
}

// Last returns the last of item.
func (q *Queue[T]) Last() T {
	if len(q.items) == 0 {
		return GetZero[T]()
	}

	q.lock.RLock()
	last := q.items[len(q.items)-1]
	q.lock.RUnlock()
	return last
}

// Copy get the copy of queue.
func (q *Queue[T]) Copy() []T {
	items := []T{}
	q.lock.RLock()
	items = append(items, q.items...)
	q.lock.RUnlock()
	return items
}

// Len returns the number of items in this queue.
func (q *Queue[T]) Len() int64 {
	q.lock.Lock()
	defer q.lock.Unlock()

	return int64(len(q.items))
}

// New is a constructor for a new concurrent safe queue.
func New[T any](hint int64) *Queue[T] {
	return &Queue[T]{
		items: make([]T, 0, hint),
	}
}

func GetZero[T any]() T {
	var result T
	return result
}
