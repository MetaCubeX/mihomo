package constant

import (
	"time"
)

type Traffic struct {
	up        chan int64
	down      chan int64
	upCount   int64
	downCount int64
	upTotal   int64
	downTotal int64
	interval  time.Duration
}

func (t *Traffic) Up() chan<- int64 {
	return t.up
}

func (t *Traffic) Down() chan<- int64 {
	return t.down
}

func (t *Traffic) Now() (up int64, down int64) {
	return t.upTotal, t.downTotal
}

func (t *Traffic) handle() {
	go t.handleCh(t.up, &t.upCount, &t.upTotal)
	go t.handleCh(t.down, &t.downCount, &t.downTotal)
}

func (t *Traffic) handleCh(ch <-chan int64, count *int64, total *int64) {
	ticker := time.NewTicker(t.interval)
	for {
		select {
		case n := <-ch:
			*count += n
		case <-ticker.C:
			*total = *count
			*count = 0
		}
	}
}

func NewTraffic(interval time.Duration) *Traffic {
	t := &Traffic{
		up:       make(chan int64),
		down:     make(chan int64),
		interval: interval,
	}
	go t.handle()
	return t
}
