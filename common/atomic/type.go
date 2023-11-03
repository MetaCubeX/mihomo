package atomic

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync/atomic"
)

type Bool struct {
	atomic.Bool
}

func NewBool(val bool) (i Bool) {
	i.Store(val)
	return
}

func (i *Bool) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.Load())
}

func (i *Bool) UnmarshalJSON(b []byte) error {
	var v bool
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	i.Store(v)
	return nil
}

func (i *Bool) String() string {
	v := i.Load()
	return strconv.FormatBool(v)
}

type Pointer[T any] struct {
	atomic.Pointer[T]
}

func NewPointer[T any](v *T) (p Pointer[T]) {
	if v != nil {
		p.Store(v)
	}
	return
}

func (p *Pointer[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Load())
}

func (p *Pointer[T]) UnmarshalJSON(b []byte) error {
	var v *T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	p.Store(v)
	return nil
}

func (p *Pointer[T]) String() string {
	return fmt.Sprint(p.Load())
}

type Int32 struct {
	atomic.Int32
}

func NewInt32(val int32) (i Int32) {
	i.Store(val)
	return
}

func (i *Int32) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.Load())
}

func (i *Int32) UnmarshalJSON(b []byte) error {
	var v int32
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	i.Store(v)
	return nil
}

func (i *Int32) String() string {
	v := i.Load()
	return strconv.FormatInt(int64(v), 10)
}

type Int64 struct {
	atomic.Int64
}

func NewInt64(val int64) (i Int64) {
	i.Store(val)
	return
}

func (i *Int64) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.Load())
}

func (i *Int64) UnmarshalJSON(b []byte) error {
	var v int64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	i.Store(v)
	return nil
}

func (i *Int64) String() string {
	v := i.Load()
	return strconv.FormatInt(int64(v), 10)
}

type Uint32 struct {
	atomic.Uint32
}

func NewUint32(val uint32) (i Uint32) {
	i.Store(val)
	return
}

func (i *Uint32) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.Load())
}

func (i *Uint32) UnmarshalJSON(b []byte) error {
	var v uint32
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	i.Store(v)
	return nil
}

func (i *Uint32) String() string {
	v := i.Load()
	return strconv.FormatUint(uint64(v), 10)
}

type Uint64 struct {
	atomic.Uint64
}

func NewUint64(val uint64) (i Uint64) {
	i.Store(val)
	return
}

func (i *Uint64) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.Load())
}

func (i *Uint64) UnmarshalJSON(b []byte) error {
	var v uint64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	i.Store(v)
	return nil
}

func (i *Uint64) String() string {
	v := i.Load()
	return strconv.FormatUint(uint64(v), 10)
}

type Uintptr struct {
	atomic.Uintptr
}

func NewUintptr(val uintptr) (i Uintptr) {
	i.Store(val)
	return
}

func (i *Uintptr) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.Load())
}

func (i *Uintptr) UnmarshalJSON(b []byte) error {
	var v uintptr
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	i.Store(v)
	return nil
}

func (i *Uintptr) String() string {
	v := i.Load()
	return strconv.FormatUint(uint64(v), 10)
}
