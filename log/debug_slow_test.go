package log

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLevelChangeWithSaturatedSubscriber(t *testing.T) {
	old := Level()
	SetLevel(ERROR)
	sub := Subscribe()
	producerDone, unsubDone := make(chan struct{}), make(chan struct{})
	var changed chan struct{}
	unsubStarted := false
	wait := func(ch <-chan struct{}, name string) {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Error(name + " did not settle")
		}
	}
	// Draining is required by the existing blocking observable contract. Wait
	// for every writer before restoring the package's global level, even on failure.
	defer func() {
		go func() {
			for range sub {
			}
		}()
		if !unsubStarted {
			go func() { UnSubscribe(sub); close(unsubDone) }()
		}
		wait(producerDone, "producer")
		wait(unsubDone, "unsubscribe")
		if changed != nil {
			wait(changed, "level writer")
		}
		SetLevel(old)
	}()
	for i := 0; i < cap(sub); i++ {
		Infoln("fill")
	}
	first := make(chan struct{})
	go func() { Infoln("overflow"); close(first); Infoln("pending"); close(producerDone) }()
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("overflow not received")
	}
	// Receiving the overflow event alone does not prove process has acquired its
	// mutex. Observe the actual blocked broadcast before starting the unregister.
	// There is one observable in this package; process sends only inside Emit.
	deadline := time.Now().Add(time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		buffer := make([]byte, 64<<10)
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if strings.Contains(stack, "[chan send]") && strings.Contains(stack, "common/observable.(*Observable[") && strings.Contains(stack, ").process(") {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		runtime.Gosched()
	}
	if !blocked {
		t.Fatal("did not reach blocked observable delivery")
	}
	unsubStarted = true
	go func() { UnSubscribe(sub); close(unsubDone) }()
	deadline = time.Now().Add(time.Second)
	for DebugEnabled() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if DebugEnabled() {
		t.Fatal("unsubscribe did not withdraw interest")
	}
	select {
	case <-unsubDone:
		t.Fatal("unsubscribe unexpectedly bypassed blocked delivery")
	default:
	}
	changed = make(chan struct{})
	go func() { SetLevel(DEBUG); close(changed) }()
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("observable backpressure held the level writer lock")
	}
}
