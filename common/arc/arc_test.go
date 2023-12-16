package arc

import (
	"testing"
)

func TestInsertion(t *testing.T) {
	cache := New[string, string](WithSize[string, string](3))
	if got, want := cache.Len(), 0; got != want {
		t.Errorf("empty cache.Len(): got %d want %d", cache.Len(), want)
	}

	const (
		k1 = "Hello"
		k2 = "Hallo"
		k3 = "Ciao"
		k4 = "Salut"

		v1 = "World"
		v2 = "Worlds"
		v3 = "Welt"
	)

	// Insert the first value
	cache.Set(k1, v1)
	if got, want := cache.Len(), 1; got != want {
		t.Errorf("insertion of key #%d: cache.Len(): got %d want %d", want, cache.Len(), want)
	}
	if got, ok := cache.Get(k1); !ok || got != v1 {
		t.Errorf("cache.Get(%v): got (%v,%t) want (%v,true)", k1, got, ok, v1)
	}

	// Replace existing value for a given key
	cache.Set(k1, v2)
	if got, want := cache.Len(), 1; got != want {
		t.Errorf("re-insertion: cache.Len(): got %d want %d", cache.Len(), want)
	}
	if got, ok := cache.Get(k1); !ok || got != v2 {
		t.Errorf("re-insertion: cache.Get(%v): got (%v,%t) want (%v,true)", k1, got, ok, v2)
	}

	// Add a second different key
	cache.Set(k2, v3)
	if got, want := cache.Len(), 2; got != want {
		t.Errorf("insertion of key #%d: cache.Len(): got %d want %d", want, cache.Len(), want)
	}
	if got, ok := cache.Get(k1); !ok || got != v2 {
		t.Errorf("cache.Get(%v): got (%v,%t) want (%v,true)", k1, got, ok, v2)
	}
	if got, ok := cache.Get(k2); !ok || got != v3 {
		t.Errorf("cache.Get(%v): got (%v,%t) want (%v,true)", k2, got, ok, v3)
	}

	// Fill cache
	cache.Set(k3, v1)
	if got, want := cache.Len(), 3; got != want {
		t.Errorf("insertion of key #%d: cache.Len(): got %d want %d", want, cache.Len(), want)
	}

	// Exceed size, this should not exceed size:
	cache.Set(k4, v1)
	if got, want := cache.Len(), 3; got != want {
		t.Errorf("insertion of key out of size: cache.Len(): got %d want %d", cache.Len(), want)
	}
}

func TestEviction(t *testing.T) {
	size := 3
	cache := New[string, string](WithSize[string, string](size))
	if got, want := cache.Len(), 0; got != want {
		t.Errorf("empty cache.Len(): got %d want %d", cache.Len(), want)
	}

	tests := []struct {
		k, v string
	}{
		{"k1", "v1"},
		{"k2", "v2"},
		{"k3", "v3"},
		{"k4", "v4"},
	}
	for i, tt := range tests[:size] {
		cache.Set(tt.k, tt.v)
		if got, want := cache.Len(), i+1; got != want {
			t.Errorf("insertion of key #%d: cache.Len(): got %d want %d", want, cache.Len(), want)
		}
	}

	// Exceed size and check we don't outgrow it:
	cache.Set(tests[size].k, tests[size].v)
	if got := cache.Len(); got != size {
		t.Errorf("insertion of overflow key #%d: cache.Len(): got %d want %d", 4, cache.Len(), size)
	}

	// Check that LRU got evicted:
	if got, ok := cache.Get(tests[0].k); ok || got != "" {
		t.Errorf("cache.Get(%v): got (%v,%t) want (<nil>,true)", tests[0].k, got, ok)
	}

	for _, tt := range tests[1:] {
		if got, ok := cache.Get(tt.k); !ok || got != tt.v {
			t.Errorf("cache.Get(%v): got (%v,%t) want (%v,true)", tt.k, got, ok, tt.v)
		}
	}
}
