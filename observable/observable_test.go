package observable

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func iterator(item []interface{}) chan interface{} {
	ch := make(chan interface{})
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
	iter := iterator([]interface{}{1, 2, 3, 4, 5})
	src := NewObservable(iter)
	data, err := src.Subscribe()
	if err != nil {
		t.Error(err)
	}
	count := 0
	for {
		_, open := <-data
		if !open {
			break
		}
		count = count + 1
	}
	if count != 5 {
		t.Error("Revc number error")
	}
}

func TestObservable_MutilSubscribe(t *testing.T) {
	iter := iterator([]interface{}{1, 2, 3, 4, 5})
	src := NewObservable(iter)
	ch1, _ := src.Subscribe()
	ch2, _ := src.Subscribe()
	count := 0

	var wg sync.WaitGroup
	wg.Add(2)
	waitCh := func(ch <-chan interface{}) {
		for {
			_, open := <-ch
			if !open {
				break
			}
			count = count + 1
		}
		wg.Done()
	}
	go waitCh(ch1)
	go waitCh(ch2)
	wg.Wait()
	if count != 10 {
		t.Error("Revc number error")
	}
}

func TestObservable_UnSubscribe(t *testing.T) {
	iter := iterator([]interface{}{1, 2, 3, 4, 5})
	src := NewObservable(iter)
	data, err := src.Subscribe()
	if err != nil {
		t.Error(err)
	}
	src.UnSubscribe(data)
	_, open := <-data
	if open {
		t.Error("Revc number error")
	}
}

func TestObservable_SubscribeGoroutineLeak(t *testing.T) {
	// waiting for other goroutine recycle
	time.Sleep(120 * time.Millisecond)
	init := runtime.NumGoroutine()
	iter := iterator([]interface{}{1, 2, 3, 4, 5})
	src := NewObservable(iter)
	max := 100

	var list []Subscription
	for i := 0; i < max; i++ {
		ch, _ := src.Subscribe()
		list = append(list, ch)
	}

	var wg sync.WaitGroup
	wg.Add(max)
	waitCh := func(ch <-chan interface{}) {
		for {
			_, open := <-ch
			if !open {
				break
			}
		}
		wg.Done()
	}

	for _, ch := range list {
		go waitCh(ch)
	}
	wg.Wait()
	now := runtime.NumGoroutine()
	if init != now {
		t.Errorf("Goroutine Leak: init %d now %d", init, now)
	}
}
