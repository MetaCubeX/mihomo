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

func transportID(rt *ReuseTransport) int64 {
	return rt.entry.transport.(*testRoundTripper).id
}

func TestManagerReuseSameEntry(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		HMaxRequestTimes: "10",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 != id2 {
		t.Fatalf("expected same transport to be reused, got %d and %d", id1, id2)
	}

	transport2.Close()
	manager.Close()
}

func TestManagerRespectMaxConnections(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "2",
		MaxConnections:   "2",
		HMaxRequestTimes: "100",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)
	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)
	transport3 := manager.GetTransport().(*ReuseTransport)
	id3 := transportID(transport3)
	transport4 := manager.GetTransport().(*ReuseTransport)
	id4 := transportID(transport4)
	transport5 := manager.GetTransport().(*ReuseTransport)
	id5 := transportID(transport5)

	if id1 == id2 {
		t.Fatal("expected the second transport to be new")
	}

	if id3 != id1 && id3 != id2 {
		t.Fatal("expected the third transport to be reused")
	}

	if id4 != id1 && id4 != id2 {
		t.Fatal("expected the fourth transport to be reused")
	}

	if id5 == id1 || id5 == id2 {
		t.Fatal("expected the fifth transport to be new")
	}

	transport1.Close()
	transport2.Close()
	transport3.Close()
	transport4.Close()
	transport5.Close()
	manager.Close()
}

func TestManagerRotateOnRequestLimit(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		HMaxRequestTimes: "1",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 == id2 {
		t.Fatalf("expected new transport after request limit, got same id %d", id1)
	}

	transport2.Close()
	manager.Close()
}

func TestManagerRotateOnReusableSecs(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		HMaxRequestTimes: "100",
		HMaxReusableSecs: "1",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	time.Sleep(1100 * time.Millisecond)
	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 == id2 {
		t.Fatalf("expected new transport after reusable timeout, got same id %d", id1)
	}

	transport2.Close()
	manager.Close()
}

func TestManagerRotateOnConnReuseLimit(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		CMaxReuseTimes:   "1",
		HMaxRequestTimes: "100",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 != id2 {
		t.Fatalf("expected first reuse to use same transport, got %d and %d", id1, id2)
	}

	transport2.Close()

	transport3 := manager.GetTransport().(*ReuseTransport)
	id3 := transportID(transport3)

	if id3 == id2 {
		t.Fatalf("expected new transport after c-max-reuse-times limit, got same id %d", id3)
	}

	transport3.Close()
	manager.Close()
}
