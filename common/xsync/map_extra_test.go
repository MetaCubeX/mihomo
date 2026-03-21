package xsync

import (
	"strconv"
	"testing"
)

func TestMapOfLoadOrStoreFn(t *testing.T) {
	const numEntries = 1000
	m := NewMap[string, int]()
	for i := 0; i < numEntries; i++ {
		v, loaded := m.LoadOrStoreFn(strconv.Itoa(i), func() int {
			return i
		})
		if loaded {
			t.Fatalf("value not computed for %d", i)
		}
		if v != i {
			t.Fatalf("values do not match for %d: %v", i, v)
		}
	}
	for i := 0; i < numEntries; i++ {
		v, loaded := m.LoadOrStoreFn(strconv.Itoa(i), func() int {
			return i
		})
		if !loaded {
			t.Fatalf("value not loaded for %d", i)
		}
		if v != i {
			t.Fatalf("values do not match for %d: %v", i, v)
		}
	}
}

func TestMapOfLoadOrStoreFn_FunctionCalledOnce(t *testing.T) {
	m := NewMap[int, int]()
	for i := 0; i < 100; {
		m.LoadOrStoreFn(i, func() (v int) {
			v, i = i, i+1
			return v
		})
	}
	m.Range(func(k, v int) bool {
		if k != v {
			t.Fatalf("%dth key is not equal to value %d", k, v)
		}
		return true
	})
}
