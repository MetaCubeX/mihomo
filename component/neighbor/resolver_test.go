package neighbor

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testMAC = MAC{2, 0, 0, 0, 0, 1}
var testIP = netip.MustParseAddr("192.0.2.10")

func testTable(t testing.TB) *table {
	t.Helper()
	tab := newTable()
	for _, e := range []event{{index: 2, link: true, name: "lan"}, {index: 2, ip: testIP, mac: testMAC}} {
		if err := tab.apply(e); err != nil {
			t.Fatal(err)
		}
	}
	return tab
}

func TestTableAddressAndInterface(t *testing.T) {
	tab := testTable(t)
	v6 := netip.MustParseAddr("fe80::1234")
	global := netip.MustParseAddr("2001:db8::1234")
	for _, ip := range []netip.Addr{v6, global, global.Next()} {
		_ = tab.apply(event{index: 2, ip: ip, mac: testMAC})
	}
	for _, ip := range []netip.Addr{testIP, netip.MustParseAddr("::ffff:192.0.2.10"), v6.WithZone("lan"), v6.WithZone("2"), global, global.Next()} {
		if got, ok := tab.lookup(0, ip); !ok || got != testMAC {
			t.Fatalf("lookup %s = %v, %v", ip, got, ok)
		}
	}
	for _, ip := range []netip.Addr{{}, netip.IPv4Unspecified(), netip.IPv6Unspecified(), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("ff02::1"), v6.WithZone("missing")} {
		if _, ok := tab.lookup(0, ip); ok {
			t.Fatalf("unexpected match for %s", ip)
		}
	}
	_ = tab.apply(event{index: 3, link: true, name: "guest"})
	_ = tab.apply(event{index: 3, ip: testIP, mac: testMAC})
	if _, ok := tab.lookup(0, testIP); ok {
		t.Fatal("ambiguous interfaces must miss even with identical MAC")
	}
	if _, ok := tab.lookup(2, testIP); !ok {
		t.Fatal("explicit interface must match")
	}
	if _, ok := tab.lookup(3, v6.WithZone("lan")); ok {
		t.Fatal("conflicting scope must miss")
	}
	_ = tab.apply(event{index: 2, link: true, name: "renamed"})
	if _, ok := tab.lookup(0, v6.WithZone("lan")); ok {
		t.Fatal("old interface name survived rename")
	}
	if _, ok := tab.lookup(0, v6.WithZone("renamed")); !ok {
		t.Fatal("new interface name missing")
	}
	_ = tab.apply(event{index: 2, link: true, remove: true})
	if _, ok := tab.lookup(2, testIP); ok {
		t.Fatal("deleted interface retained neighbors")
	}
	if tab.count != 1 {
		t.Fatalf("count = %d", tab.count)
	}
	_ = tab.apply(event{index: 3, ip: testIP, remove: true})
	if len(tab.byIP) != 0 || tab.count != 0 {
		t.Fatal("delete retained empty entries")
	}
}

func TestTableCapacityAndReplacement(t *testing.T) {
	tab := testTable(t)
	tab.count = maxEntries
	replacement := MAC{2, 0, 0, 0, 0, 2}
	if err := tab.apply(event{index: 2, ip: testIP, mac: replacement}); err != nil {
		t.Fatal(err)
	}
	if got, _ := tab.lookup(0, testIP); got != replacement {
		t.Fatal("MAC change lost")
	}
	if err := tab.apply(event{index: 2, ip: testIP.Next(), mac: testMAC}); !errors.Is(err, errCapacity) {
		t.Fatal("capacity not enforced", err)
	}
	if _, ok := tab.lookup(0, testIP.Next()); ok {
		t.Fatal("over-capacity record published")
	}
}

func TestNeighborOnUnknownInterface(t *testing.T) {
	tab := testTable(t)
	if err := tab.apply(event{index: 99, ip: testIP, mac: testMAC}); !errors.Is(err, errUnknownInterface) {
		t.Fatal("unknown interface must trigger resync, not hide a potentially ambiguous address", err)
	}
}

type fakeBatch struct {
	events []event
	err    error
}
type fakeBackend struct {
	snapshot   *table
	initialErr error
	batches    chan fakeBatch
	closed     chan struct{}
}

func (b *fakeBackend) Snapshot(context.Context) (*table, error) { return b.snapshot, b.initialErr }
func (b *fakeBackend) Next(ctx context.Context) ([]event, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case batch := <-b.batches:
		return batch.events, batch.err
	}
}
func (b *fakeBackend) Close() error { close(b.closed); return nil }
func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestResolverLifecycleRecovery(t *testing.T) {
	first := &fakeBackend{snapshot: testTable(t), batches: make(chan fakeBatch), closed: make(chan struct{})}
	second := &fakeBackend{snapshot: testTable(t), batches: make(chan fakeBatch), closed: make(chan struct{})}
	var opens atomic.Int32
	r := &Resolver{open: func() (backend, error) {
		if opens.Add(1) == 1 {
			return first, nil
		}
		return second, nil
	}}
	if _, ok := r.Lookup(0, testIP); ok || opens.Load() != 0 {
		t.Fatal("idle resolver performed work")
	}
	r.SetEnabled(false)
	r.SetEnabled(true)
	defer r.SetEnabled(false)
	r.SetEnabled(true)
	if opens.Load() != 1 {
		t.Fatal("duplicate subscription")
	}
	if _, ok := r.Lookup(0, testIP); !ok {
		t.Fatal("initialization did not publish snapshot")
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					r.Lookup(0, testIP)
				}
			}
		}()
	}
	defer func() { close(stop); wg.Wait() }()
	first.batches <- fakeBatch{events: []event{{index: 2, ip: testIP, remove: true}}}
	eventually(t, func() bool { _, ok := r.Lookup(0, testIP); return !ok })
	first.batches <- fakeBatch{events: []event{{index: 2, ip: testIP, mac: testMAC}}}
	eventually(t, func() bool { _, ok := r.Lookup(0, testIP); return ok })
	first.batches <- fakeBatch{err: errors.New("notifications lost")}
	<-first.closed
	eventually(t, func() bool { _, ok := r.Lookup(0, testIP); return !ok })
	eventually(t, func() bool { _, ok := r.Lookup(0, testIP); return ok && opens.Load() == 2 })
	r.SetEnabled(false)
	if _, ok := r.Lookup(0, testIP); ok {
		t.Fatal("shutdown retained cache")
	}
	select {
	case <-second.closed:
	default:
		t.Fatal("backend not closed")
	}
}

func TestResolverInitialFailure(t *testing.T) {
	b := &fakeBackend{initialErr: errors.New("dump failed"), closed: make(chan struct{})}
	r := &Resolver{open: func() (backend, error) { return b, nil }}
	r.SetEnabled(true)
	defer r.SetEnabled(false)
	if _, ok := r.Lookup(0, testIP); ok {
		t.Fatal("failed snapshot was published")
	}
	<-b.closed
}

func BenchmarkLookup(b *testing.B) {
	r := New(nil)
	r.replace(testTable(b))
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.Lookup(0, testIP)
		}
	})
}
