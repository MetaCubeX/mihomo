package singledo

import (
	"sync"
	"time"
)

type call struct {
	wg  sync.WaitGroup
	val interface{}
	err error
}

type Single struct {
	mux    sync.Mutex
	last   int64
	wait   int64
	call   *call
	result *Result
}

type Result struct {
	Val interface{}
	Err error
}

func (s *Single) Do(fn func() (interface{}, error)) (v interface{}, err error, shared bool) {
	s.mux.Lock()
	now := time.Now().Unix()
	if now < s.last+s.wait {
		s.mux.Unlock()
		return s.result.Val, s.result.Err, true
	}

	if call := s.call; call != nil {
		s.mux.Unlock()
		call.wg.Wait()
		return call.val, call.err, true
	}

	call := &call{}
	call.wg.Add(1)
	s.call = call
	s.mux.Unlock()
	call.val, call.err = fn()
	s.call = nil
	s.result = &Result{call.val, call.err}
	s.last = now
	return call.val, call.err, false
}

func NewSingle(wait time.Duration) *Single {
	return &Single{wait: int64(wait)}
}
