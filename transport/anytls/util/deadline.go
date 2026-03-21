package util

import (
	"sync"
	"time"
)

func NewDeadlineWatcher(ddl time.Duration, timeOut func()) (done func()) {
	t := time.NewTimer(ddl)
	closeCh := make(chan struct{})
	go func() {
		defer t.Stop()
		select {
		case <-closeCh:
		case <-t.C:
			timeOut()
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(closeCh)
		})
	}
}
