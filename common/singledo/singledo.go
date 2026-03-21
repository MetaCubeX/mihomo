package singledo

import (
	"sync"
	"time"
)

type call[T any] struct {
	wg  sync.WaitGroup
	val T
	err error
}

type Single[T any] struct {
	mux    sync.Mutex
	wait   time.Duration
	call   *call[T]
	result *Result[T]
}

type Result[T any] struct {
	Val  T
	Err  error
	Time time.Time
}

// Do single.Do likes sync.singleFlight
func (s *Single[T]) Do(fn func() (T, error)) (v T, err error, shared bool) {
	s.mux.Lock()
	result := s.result
	if result != nil && time.Since(result.Time) < s.wait {
		s.mux.Unlock()
		return result.Val, result.Err, true
	}
	s.result = nil // The result has expired, clear it

	if callM := s.call; callM != nil {
		s.mux.Unlock()
		callM.wg.Wait()
		return callM.val, callM.err, true
	}

	callM := &call[T]{}
	callM.wg.Add(1)
	s.call = callM
	s.mux.Unlock()
	callM.val, callM.err = fn()
	callM.wg.Done()

	s.mux.Lock()
	if s.call == callM { // maybe reset when fn is running
		s.call = nil
		s.result = &Result[T]{callM.val, callM.err, time.Now()}
	}
	s.mux.Unlock()
	return callM.val, callM.err, false
}

func (s *Single[T]) Reset() {
	s.mux.Lock()
	s.call = nil
	s.result = nil
	s.mux.Unlock()
}

func NewSingle[T any](wait time.Duration) *Single[T] {
	return &Single[T]{wait: wait}
}
