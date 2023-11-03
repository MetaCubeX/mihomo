package observable

import (
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/atomic"

	"github.com/stretchr/testify/assert"
)

func iterator[T any](item []T) chan T {
	ch := make(chan T)
	go func() {
		time.Sleep(100 * time.Millisecond)
		for _, elm := range item {
			ch <- elm
		}
		close(ch)
	}()
	return ch
}

func TestObservable(t *testing.T) {
	iter := iterator[int]([]int{1, 2, 3, 4, 5})
	src := NewObservable[int](iter)
	data, err := src.Subscribe()
	assert.Nil(t, err)
	count := 0
	for range data {
		count++
	}
	assert.Equal(t, count, 5)
}

func TestObservable_MultiSubscribe(t *testing.T) {
	iter := iterator[int]([]int{1, 2, 3, 4, 5})
	src := NewObservable[int](iter)
	ch1, _ := src.Subscribe()
	ch2, _ := src.Subscribe()
	count := atomic.NewInt32(0)

	var wg sync.WaitGroup
	wg.Add(2)
	waitCh := func(ch <-chan int) {
		for range ch {
			count.Add(1)
		}
		wg.Done()
	}
	go waitCh(ch1)
	go waitCh(ch2)
	wg.Wait()
	assert.Equal(t, int32(10), count.Load())
}

func TestObservable_UnSubscribe(t *testing.T) {
	iter := iterator[int]([]int{1, 2, 3, 4, 5})
	src := NewObservable[int](iter)
	data, err := src.Subscribe()
	assert.Nil(t, err)
	src.UnSubscribe(data)
	_, open := <-data
	assert.False(t, open)
}

func TestObservable_SubscribeClosedSource(t *testing.T) {
	iter := iterator[int]([]int{1})
	src := NewObservable[int](iter)
	data, _ := src.Subscribe()
	<-data

	_, closed := src.Subscribe()
	assert.NotNil(t, closed)
}

func TestObservable_UnSubscribeWithNotExistSubscription(t *testing.T) {
	sub := Subscription[int](make(chan int))
	iter := iterator[int]([]int{1})
	src := NewObservable[int](iter)
	src.UnSubscribe(sub)
}

func TestObservable_SubscribeGoroutineLeak(t *testing.T) {
	iter := iterator[int]([]int{1, 2, 3, 4, 5})
	src := NewObservable[int](iter)
	max := 100

	var list []Subscription[int]
	for i := 0; i < max; i++ {
		ch, _ := src.Subscribe()
		list = append(list, ch)
	}

	var wg sync.WaitGroup
	wg.Add(max)
	waitCh := func(ch <-chan int) {
		for range ch {
		}
		wg.Done()
	}

	for _, ch := range list {
		go waitCh(ch)
	}
	wg.Wait()

	for _, sub := range list {
		_, more := <-sub
		assert.False(t, more)
	}

	_, more := <-list[0]
	assert.False(t, more)
}

func Benchmark_Observable_1000(b *testing.B) {
	ch := make(chan int)
	o := NewObservable[int](ch)
	num := 1000

	subs := []Subscription[int]{}
	for i := 0; i < num; i++ {
		sub, _ := o.Subscribe()
		subs = append(subs, sub)
	}

	wg := sync.WaitGroup{}
	wg.Add(num)

	b.ResetTimer()
	for _, sub := range subs {
		go func(s Subscription[int]) {
			for range s {
			}
			wg.Done()
		}(sub)
	}

	for i := 0; i < b.N; i++ {
		ch <- i
	}

	close(ch)
	wg.Wait()
}
