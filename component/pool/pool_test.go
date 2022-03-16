package pool

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func lg() Factory {
	initial := -1
	return func(context.Context) (any, error) {
		initial++
		return initial, nil
	}
}

func TestPool_Basic(t *testing.T) {
	g := lg()
	pool := New(g)

	elm, _ := pool.Get()
	assert.Equal(t, 0, elm.(int))
	pool.Put(elm)
	elm, _ = pool.Get()
	assert.Equal(t, 0, elm.(int))
	elm, _ = pool.Get()
	assert.Equal(t, 1, elm.(int))
}

func TestPool_MaxSize(t *testing.T) {
	g := lg()
	size := 5
	pool := New(g, WithSize(size))

	items := []any{}

	for i := 0; i < size; i++ {
		item, _ := pool.Get()
		items = append(items, item)
	}

	extra, _ := pool.Get()
	assert.Equal(t, size, extra.(int))

	for _, item := range items {
		pool.Put(item)
	}

	pool.Put(extra)

	for _, item := range items {
		elm, _ := pool.Get()
		assert.Equal(t, item.(int), elm.(int))
	}
}

func TestPool_MaxAge(t *testing.T) {
	g := lg()
	pool := New(g, WithAge(20))

	elm, _ := pool.Get()
	pool.Put(elm)

	elm, _ = pool.Get()
	assert.Equal(t, 0, elm.(int))
	pool.Put(elm)

	time.Sleep(time.Millisecond * 22)
	elm, _ = pool.Get()
	assert.Equal(t, 1, elm.(int))
}
