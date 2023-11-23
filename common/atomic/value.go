package atomic

import (
	"encoding/json"
	"sync/atomic"
)

func DefaultValue[T any]() T {
	var defaultValue T
	return defaultValue
}

type TypedValue[T any] struct {
	_     noCopy
	value atomic.Value
}

func (t *TypedValue[T]) Load() T {
	value := t.value.Load()
	if value == nil {
		return DefaultValue[T]()
	}
	return value.(T)
}

func (t *TypedValue[T]) Store(value T) {
	t.value.Store(value)
}

func (t *TypedValue[T]) Swap(new T) T {
	old := t.value.Swap(new)
	if old == nil {
		return DefaultValue[T]()
	}
	return old.(T)
}

func (t *TypedValue[T]) CompareAndSwap(old, new T) bool {
	return t.value.CompareAndSwap(old, new)
}

func (t *TypedValue[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Load())
}

func (t *TypedValue[T]) UnmarshalJSON(b []byte) error {
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	t.Store(v)
	return nil
}

func NewTypedValue[T any](t T) (v TypedValue[T]) {
	v.Store(t)
	return
}

type noCopy struct{}

// Lock is a no-op used by -copylocks checker from `go vet`.
func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
