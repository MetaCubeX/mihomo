package utils

import (
	"sync/atomic"
	"time"
)

type AtomicTime struct {
	v atomic.Value
}

func NewAtomicTime(t time.Time) *AtomicTime {
	a := &AtomicTime{}
	a.Set(t)
	return a
}

func (t *AtomicTime) Set(new time.Time) {
	t.v.Store(new)
}

func (t *AtomicTime) Get() time.Time {
	return t.v.Load().(time.Time)
}
