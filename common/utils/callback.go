package utils

import (
	"io"
	"sync"

	list "github.com/bahlo/generic-list-go"
)

type Callback[T any] struct {
	list  list.List[func(T)]
	mutex sync.RWMutex
}

func NewCallback[T any]() *Callback[T] {
	return &Callback[T]{}
}

func (c *Callback[T]) Register(item func(T)) io.Closer {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	element := c.list.PushBack(item)
	return &callbackCloser[T]{
		element:  element,
		callback: c,
	}
}

func (c *Callback[T]) Emit(item T) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	for element := c.list.Front(); element != nil; element = element.Next() {
		go element.Value(item)
	}
}

type callbackCloser[T any] struct {
	element  *list.Element[func(T)]
	callback *Callback[T]
	once     sync.Once
}

func (c *callbackCloser[T]) Close() error {
	c.once.Do(func() {
		c.callback.mutex.Lock()
		defer c.callback.mutex.Unlock()
		c.callback.list.Remove(c.element)
	})
	return nil
}
