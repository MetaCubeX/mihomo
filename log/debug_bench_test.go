package log

import (
	"sync"
	"testing"
	"time"
)

func TestDebugSubscription(t *testing.T) {
	old := Level()
	SetLevel(INFO)
	defer SetLevel(old)
	sub := Subscribe()
	defer UnSubscribe(sub)
	Debugln("test-debug-%d", 1)
	select {
	case event := <-sub:
		if event.LogLevel != DEBUG || event.Payload != "test-debug-1" {
			t.Fatalf("debug subscription changed: %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal INFO suppressed a subscribed DEBUG event")
	}
}

func BenchmarkDebug(b *testing.B) {
	old := Level()
	SetLevel(INFO)
	defer SetLevel(old)
	for _, subscribed := range []bool{false, true} {
		name := "no-subscriber"
		if subscribed {
			name = "debug-subscriber"
		}
		b.Run(name, func(b *testing.B) {
			var finish func()
			if subscribed {
				sub := Subscribe()
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range sub {
					}
				}()
				finish = func() { UnSubscribe(sub); wg.Wait() }
				defer finish()
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Debugln("[DNS] cache hit %s --> %s, expire at %s", "matrix.invalid.", "198.18.0.1", "2030-01-01 00:00:00")
			}
		})
	}
}
