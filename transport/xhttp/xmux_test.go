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
	panic("not used in xmux manager unit tests")
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

func TestXMuxReuseSameEntry(t *testing.T) {
	var created atomic.Int64

	manager := newXMuxManager(&XMuxConfig{
		MaxConnections:   1,
		MaxConcurrency:   1,
		HMaxRequestTimes: 10,
	})

	entry1, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	id1 := transportID(entry1.uploadTransport)

	manager.release(entry1)

	entry2, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	id2 := transportID(entry2.uploadTransport)

	if id1 != id2 {
		t.Fatalf("expected same transport to be reused, got %d and %d", id1, id2)
	}

	manager.release(entry2)
	manager.Close()
}

func TestXMuxRespectMaxConnections(t *testing.T) {
	var created atomic.Int64

	manager := newXMuxManager(&XMuxConfig{
		MaxConnections:   2,
		MaxConcurrency:   1,
		HMaxRequestTimes: 100,
	})

	entry1, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	entry2, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if entry1 == entry2 {
		t.Fatal("expected different entries for first two allocations")
	}

	id1 := transportID(entry1.uploadTransport)
	id2 := transportID(entry2.uploadTransport)

	entry3, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	id3 := transportID(entry3.uploadTransport)

	if id3 != id1 && id3 != id2 {
		t.Fatalf("expected reuse of existing entry, got new transport id %d", id3)
	}

	manager.release(entry1)
	manager.release(entry2)
	manager.release(entry3)
	manager.Close()
}

func TestXMuxRotateOnRequestLimit(t *testing.T) {
	var created atomic.Int64

	manager := newXMuxManager(&XMuxConfig{
		MaxConnections:   1,
		MaxConcurrency:   1,
		HMaxRequestTimes: 1,
	})

	entry1, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	id1 := transportID(entry1.uploadTransport)

	manager.release(entry1)

	entry2, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	id2 := transportID(entry2.uploadTransport)

	if id1 == id2 {
		t.Fatalf("expected new transport after request limit, got same id %d", id1)
	}

	manager.release(entry2)
	manager.Close()
}

func TestXMuxRotateOnReusableSecs(t *testing.T) {
	var created atomic.Int64

	manager := newXMuxManager(&XMuxConfig{
		MaxConnections:   1,
		MaxConcurrency:   1,
		HMaxRequestTimes: 100,
		HMaxReusableSecs: 1,
	})

	entry1, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	id1 := transportID(entry1.uploadTransport)

	time.Sleep(1100 * time.Millisecond)
	manager.release(entry1)

	entry2, err := manager.getOrCreate(
		makeTestTransportFactory(&created),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	id2 := transportID(entry2.uploadTransport)

	if id1 == id2 {
		t.Fatalf("expected new transport after reusable timeout, got same id %d", id1)
	}

	manager.release(entry2)
	manager.Close()
}
