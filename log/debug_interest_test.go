package log

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type debugStringer struct{ calls *atomic.Int64 }

func (s debugStringer) String() string { s.calls.Add(1); return "formatted" }

func TestDebugInterest(t *testing.T) {
	old := Level()
	SetLevel(INFO)
	defer SetLevel(old)
	calls := new(atomic.Int64)
	value := debugStringer{calls}
	Debugln("%s", value)
	SingLogger.Debug(value)
	SingInfoToDebugLogger.Info(value)
	if calls.Load() != 0 || DebugEnabled() {
		t.Fatal("unused DEBUG was formatted")
	}
	info := SubscribeLevel(INFO)
	defer UnSubscribe(info)
	Debugln("%s", value)
	if calls.Load() != 0 || DebugEnabled() {
		t.Fatal("INFO subscription enabled DEBUG")
	}
	debug := Subscribe()
	defer UnSubscribe(debug)
	Debugln("%s", value)
	select {
	case event := <-debug:
		if event.Payload != "formatted" || event.LogLevel != DEBUG {
			t.Fatal(event)
		}
	case <-time.After(time.Second):
		t.Fatal("DEBUG subscriber lost event")
	}
	if calls.Load() != 1 {
		t.Fatal("DEBUG payload not formatted once", calls.Load())
	}
	SetLevel(DEBUG)
	UnSubscribe(debug)
	UnSubscribe(debug)
	if !DebugEnabled() {
		t.Fatal("terminal DEBUG lost interest during handoff")
	}
	SetLevel(INFO)
	if DebugEnabled() {
		t.Fatal("last DEBUG interest retained")
	}
	UnSubscribe(info)
}

func TestDebugInterestConcurrent(t *testing.T) {
	old := Level()
	SetLevel(DEBUG)
	defer SetLevel(old)
	// Each writer transfers interest with overlap. There is continuously at least
	// one receiver; the aggregate guard must never briefly publish false.
	var wg sync.WaitGroup
	var stop atomic.Bool
	var missing atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			if !DebugEnabled() {
				missing.Store(true)
			}
		}
	}()
	for i := 0; i < 1000; i++ {
		sub := SubscribeLevel(DEBUG)
		SetLevel(INFO)
		SetLevel(DEBUG)
		UnSubscribe(sub)
	}
	stop.Store(true)
	wg.Wait()
	if missing.Load() {
		t.Fatal("DEBUG interest vanished during an overlapping handoff")
	}
}
