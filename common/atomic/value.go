package atomic

import (
	"encoding/json"
	"sync/atomic"
)

type TypedValue[T any] struct {
	value atomic.Pointer[T]
}

func (t *TypedValue[T]) Load() (v T) {
	v, _ = t.LoadOk()
	return
}

func (t *TypedValue[T]) LoadOk() (v T, ok bool) {
	value := t.value.Load()
	if value == nil {
		return
	}
	return *value, true
}

func (t *TypedValue[T]) Store(value T) {
	t.value.Store(&value)
}

func (t *TypedValue[T]) Swap(new T) (v T) {
	old := t.value.Swap(&new)
	if old == nil {
		return
	}
	return *old
}

func (t *TypedValue[T]) CompareAndSwap(old, new T) bool {
	for {
		currentP := t.value.Load()
		var currentValue T
		if currentP != nil {
			currentValue = *currentP
		}
		// Compare old and current via runtime equality check.
		if any(currentValue) != any(old) {
			return false
		}
		if t.value.CompareAndSwap(currentP, &new) {
			return true
		}
	}
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

func (t *TypedValue[T]) MarshalYAML() (any, error) {
	return t.Load(), nil
}

func (t *TypedValue[T]) UnmarshalYAML(unmarshal func(any) error) error {
	var v T
	if err := unmarshal(&v); err != nil {
		return err
	}
	t.Store(v)
	return nil
}

func NewTypedValue[T any](t T) (v TypedValue[T]) {
	v.Store(t)
	return
}
