package xhttp

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
)

type testRoundTripper struct {
	id int64
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	panic("not used in reuse manager unit tests")
}

func makeTestTransportFactory(counter *atomic.Int64) TransportMaker {
	return func() http.RoundTripper {
		id := counter.Add(1)
		return &testRoundTripper{id: id}
	}
}

func transportID(rt http.RoundTripper) int64 {
	return rt.(*testRoundTripper).id
}

func TestManagerReuseSameEntry(t *testing.T) {
	var created atomic.Int64

	manager := newReuseManager(&ReuseConfig{
		MaxConnections:   "1",
		MaxConcurrency:   "1",
		HMaxRequestTimes: "10",
	})

	entry1, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	id1 := transportID(entry1.transport)

	manager.release(entry1)

	entry2, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	id2 := transportID(entry2.transport)

	if id1 != id2 {
		t.Fatalf("expected same transport to be reused, got %d and %d", id1, id2)
	}

	manager.release(entry2)
	manager.Close()
}

func TestManagerRespectMaxConnections(t *testing.T) {
	var created atomic.Int64

	manager := newReuseManager(&ReuseConfig{
		MaxConnections:   "2",
		MaxConcurrency:   "1",
		HMaxRequestTimes: "100",
	})

	entry1, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	if entry1 == nil {
		t.Fatal("expected first entry")
	}

	entry2, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	if entry2 == nil {
		t.Fatal("expected second entry")
	}

	if entry1 == entry2 {
		t.Fatal("expected different entries for first two allocations")
	}

	entry3, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err == nil {
		t.Fatal("expected error when max-connections reached and all entries are at max-concurrency")
	}
	if entry3 != nil {
		t.Fatal("expected nil entry on allocation failure")
	}

	manager.release(entry1)
	manager.release(entry2)
	manager.Close()
}

func TestManagerRotateOnRequestLimit(t *testing.T) {
	var created atomic.Int64

	manager := newReuseManager(&ReuseConfig{
		MaxConnections:   "1",
		MaxConcurrency:   "1",
		HMaxRequestTimes: "1",
	})

	entry1, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	id1 := transportID(entry1.transport)

	manager.release(entry1)

	entry2, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	id2 := transportID(entry2.transport)

	if id1 == id2 {
		t.Fatalf("expected new transport after request limit, got same id %d", id1)
	}

	manager.release(entry2)
	manager.Close()
}

func TestManagerRotateOnReusableSecs(t *testing.T) {
	var created atomic.Int64

	manager := newReuseManager(&ReuseConfig{
		MaxConnections:   "1",
		MaxConcurrency:   "1",
		HMaxRequestTimes: "100",
		HMaxReusableSecs: "1",
	})

	entry1, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	id1 := transportID(entry1.transport)

	time.Sleep(1100 * time.Millisecond)
	manager.release(entry1)

	entry2, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	id2 := transportID(entry2.transport)

	if id1 == id2 {
		t.Fatalf("expected new transport after reusable timeout, got same id %d", id1)
	}

	manager.release(entry2)
	manager.Close()
}

func TestManagerRotateOnConnReuseLimit(t *testing.T) {
	var created atomic.Int64

	manager := newReuseManager(&ReuseConfig{
		MaxConnections:   "1",
		MaxConcurrency:   "1",
		CMaxReuseTimes:   "1",
		HMaxRequestTimes: "100",
	})

	entry1, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	id1 := transportID(entry1.transport)

	manager.release(entry1)

	entry2, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	id2 := transportID(entry2.transport)

	if id1 != id2 {
		t.Fatalf("expected first reuse to use same transport, got %d and %d", id1, id2)
	}

	manager.release(entry2)

	entry3, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
	)
	if err != nil {
		t.Fatal(err)
	}
	id3 := transportID(entry3.transport)

	if id3 == id2 {
		t.Fatalf("expected new transport after c-max-reuse-times limit, got same id %d", id3)
	}

	manager.release(entry3)
	manager.Close()
}
