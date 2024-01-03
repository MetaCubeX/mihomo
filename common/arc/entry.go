package arc

import (
	list "github.com/bahlo/generic-list-go"
)

type entry[K comparable, V any] struct {
	key     K
	value   V
	ll      *list.List[*entry[K, V]]
	el      *list.Element[*entry[K, V]]
	ghost   bool
	expires int64
}

func (e *entry[K, V]) setLRU(list *list.List[*entry[K, V]]) {
	e.detach()
	e.ll = list
	e.el = e.ll.PushBack(e)
}

func (e *entry[K, V]) setMRU(list *list.List[*entry[K, V]]) {
	e.detach()
	e.ll = list
	e.el = e.ll.PushFront(e)
}

func (e *entry[K, V]) detach() {
	if e.ll != nil {
		e.ll.Remove(e.el)
	}
}
