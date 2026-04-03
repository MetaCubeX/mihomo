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

func TestXMuxRespectMaxConnections(t *testing.T) {
	var created atomic.Int64

	manager := newXMuxManager(&XMuxConfig{
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

func TestXMuxRotateOnRequestLimit(t *testing.T) {
	var created atomic.Int64

	manager := newXMuxManager(&XMuxConfig{
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

func TestXMuxRotateOnReusableSecs(t *testing.T) {
	var created atomic.Int64

	manager := newXMuxManager(&XMuxConfig{
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

func TestXMuxRotateOnConnReuseLimit(t *testing.T) {
	var created atomic.Int64

	manager := newXMuxManager(&XMuxConfig{
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

func TestXMuxDownloadConfigOverride(t *testing.T) {
	cfg := &XMuxConfig{
		MaxConnections:   "1",
		MaxConcurrency:   "2",
		CMaxReuseTimes:   "3",
		HMaxRequestTimes: "4",
		HMaxReusableSecs: "5",
		Download: &XMuxConfig{
			MaxConnections:   "11",
			MaxConcurrency:   "12",
			CMaxReuseTimes:   "13",
			HMaxRequestTimes: "14",
			HMaxReusableSecs: "15",
		},
	}

	maxConn, maxConc, err := cfg.ResolveDownloadManagerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if maxConn != 11 || maxConc != 12 {
		t.Fatalf("unexpected download manager config: got (%d, %d), want (11, 12)", maxConn, maxConc)
	}

	reuse, err := cfg.ResolveDownloadConnReuseConfig()
	if err != nil {
		t.Fatal(err)
	}
	if reuse != 13 {
		t.Fatalf("unexpected download conn reuse config: got %d, want 13", reuse)
	}

	reqTimes, reusableSecs, err := cfg.ResolveDownloadEntryConfig()
	if err != nil {
		t.Fatal(err)
	}
	if reqTimes != 14 || reusableSecs != 15 {
		t.Fatalf("unexpected download entry config: got (%d, %d), want (14, 15)", reqTimes, reusableSecs)
	}
}

func TestXMuxDownloadConfigFallbackToBase(t *testing.T) {
	cfg := &XMuxConfig{
		MaxConnections:   "1",
		MaxConcurrency:   "2",
		CMaxReuseTimes:   "3",
		HMaxRequestTimes: "4",
		HMaxReusableSecs: "5",
	}

	maxConn, maxConc, err := cfg.ResolveDownloadManagerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if maxConn != 1 || maxConc != 2 {
		t.Fatalf("unexpected fallback download manager config: got (%d, %d), want (1, 2)", maxConn, maxConc)
	}

	reuse, err := cfg.ResolveDownloadConnReuseConfig()
	if err != nil {
		t.Fatal(err)
	}
	if reuse != 3 {
		t.Fatalf("unexpected fallback download conn reuse config: got %d, want 3", reuse)
	}

	reqTimes, reusableSecs, err := cfg.ResolveDownloadEntryConfig()
	if err != nil {
		t.Fatal(err)
	}
	if reqTimes != 4 || reusableSecs != 5 {
		t.Fatalf("unexpected fallback download entry config: got (%d, %d), want (4, 5)", reqTimes, reusableSecs)
	}
}

func TestXMuxDownloadConfigPartialOverride(t *testing.T) {
	cfg := &XMuxConfig{
		MaxConnections:   "1",
		MaxConcurrency:   "2",
		CMaxReuseTimes:   "3",
		HMaxRequestTimes: "4",
		HMaxReusableSecs: "5",
		Download: &XMuxConfig{
			MaxConnections: "11",
		},
	}

	maxConn, maxConc, err := cfg.ResolveDownloadManagerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if maxConn != 11 || maxConc != 2 {
		t.Fatalf("unexpected partial override manager config: got (%d, %d), want (11, 2)", maxConn, maxConc)
	}

	reuse, err := cfg.ResolveDownloadConnReuseConfig()
	if err != nil {
		t.Fatal(err)
	}
	if reuse != 3 {
		t.Fatalf("unexpected partial override reuse config: got %d, want 3", reuse)
	}

	reqTimes, reusableSecs, err := cfg.ResolveDownloadEntryConfig()
	if err != nil {
		t.Fatal(err)
	}
	if reqTimes != 4 || reusableSecs != 5 {
		t.Fatalf("unexpected partial override entry config: got (%d, %d), want (4, 5)", reqTimes, reusableSecs)
	}
}
