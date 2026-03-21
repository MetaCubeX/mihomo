package atomic

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
)

type Int32Enum[T ~int32] struct {
	value atomic.Int32
}

func (i *Int32Enum[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.Load())
}

func (i *Int32Enum[T]) UnmarshalJSON(b []byte) error {
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	i.Store(v)
	return nil
}

func (i *Int32Enum[T]) MarshalYAML() (any, error) {
	return i.Load(), nil
}

func (i *Int32Enum[T]) UnmarshalYAML(unmarshal func(any) error) error {
	var v T
	if err := unmarshal(&v); err != nil {
		return err
	}
	i.Store(v)
	return nil
}

func (i *Int32Enum[T]) String() string {
	return fmt.Sprint(i.Load())
}

func (i *Int32Enum[T]) Store(v T) {
	i.value.Store(int32(v))
}

func (i *Int32Enum[T]) Load() T {
	return T(i.value.Load())
}

func (i *Int32Enum[T]) Swap(new T) T {
	return T(i.value.Swap(int32(new)))
}

func (i *Int32Enum[T]) CompareAndSwap(old, new T) bool {
	return i.value.CompareAndSwap(int32(old), int32(new))
}

func NewInt32Enum[T ~int32](v T) *Int32Enum[T] {
	a := &Int32Enum[T]{}
	a.Store(v)
	return a
}
