package singledo

import (
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/atomic"

	"github.com/stretchr/testify/assert"
)

func TestBasic(t *testing.T) {
	single := NewSingle[int](time.Millisecond * 30)
	foo := 0
	shardCount := atomic.NewInt32(0)
	call := func() (int, error) {
		foo++
		time.Sleep(time.Millisecond * 5)
		return 0, nil
	}

	var wg sync.WaitGroup
	const n = 5
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			_, _, shard := single.Do(call)
			if shard {
				shardCount.Add(1)
			}
			wg.Done()
		}()
	}

	wg.Wait()
	assert.Equal(t, 1, foo)
	assert.Equal(t, int32(4), shardCount.Load())
}

func TestTimer(t *testing.T) {
	single := NewSingle[int](time.Millisecond * 30)
	foo := 0
	callM := func() (int, error) {
		foo++
		return 0, nil
	}

	_, _, _ = single.Do(callM)
	time.Sleep(10 * time.Millisecond)
	_, _, shard := single.Do(callM)

	assert.Equal(t, 1, foo)
	assert.True(t, shard)
}

func TestReset(t *testing.T) {
	single := NewSingle[int](time.Millisecond * 30)
	foo := 0
	callM := func() (int, error) {
		foo++
		return 0, nil
	}

	_, _, _ = single.Do(callM)
	single.Reset()
	_, _, _ = single.Do(callM)

	assert.Equal(t, 2, foo)
}
