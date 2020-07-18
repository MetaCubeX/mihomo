package singledo

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBasic(t *testing.T) {
	single := NewSingle(time.Millisecond * 30)
	foo := 0
	var shardCount int32 = 0
	call := func() (interface{}, error) {
		foo++
		time.Sleep(time.Millisecond * 5)
		return nil, nil
	}

	var wg sync.WaitGroup
	const n = 5
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			_, _, shard := single.Do(call)
			if shard {
				atomic.AddInt32(&shardCount, 1)
			}
			wg.Done()
		}()
	}

	wg.Wait()
	assert.Equal(t, 1, foo)
	assert.Equal(t, int32(4), shardCount)
}

func TestTimer(t *testing.T) {
	single := NewSingle(time.Millisecond * 30)
	foo := 0
	call := func() (interface{}, error) {
		foo++
		return nil, nil
	}

	single.Do(call)
	time.Sleep(10 * time.Millisecond)
	_, _, shard := single.Do(call)

	assert.Equal(t, 1, foo)
	assert.True(t, shard)
}

func TestReset(t *testing.T) {
	single := NewSingle(time.Millisecond * 30)
	foo := 0
	call := func() (interface{}, error) {
		foo++
		return nil, nil
	}

	single.Do(call)
	single.Reset()
	single.Do(call)

	assert.Equal(t, 2, foo)
}
