package collections

import "sync"

type (
	stack struct {
		top    *node
		length int
		lock   *sync.RWMutex
	}

	node struct {
		value interface{}
		prev  *node
	}
)

// NewStack Create a new stack
func NewStack() *stack {
	return &stack{nil, 0, &sync.RWMutex{}}
}

// Len Return the number of items in the stack
func (this *stack) Len() int {
	return this.length
}

// Peek View the top item on the stack
func (this *stack) Peek() interface{} {
	if this.length == 0 {
		return nil
	}
	return this.top.value
}

// Pop the top item of the stack and return it
func (this *stack) Pop() interface{} {
	this.lock.Lock()
	defer this.lock.Unlock()
	if this.length == 0 {
		return nil
	}
	n := this.top
	this.top = n.prev
	this.length--
	return n.value
}

// Push a value onto the top of the stack
func (this *stack) Push(value interface{}) {
	this.lock.Lock()
	defer this.lock.Unlock()
	n := &node{value, this.top}
	this.top = n
	this.length++
}
