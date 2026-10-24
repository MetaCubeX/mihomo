package outboundgroup

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type urlTestProxy struct {
	C.Proxy
	name  string
	alive bool
	delay uint16
}

func (p *urlTestProxy) Name() string                { return p.name }
func (p *urlTestProxy) AliveForTestUrl(string) bool { return p.alive }
func (p *urlTestProxy) LastDelayForTestUrl(string) uint16 {
	if !p.alive {
		return 0xffff
	}
	return p.delay
}

type urlTestProvider struct {
	P.ProxyProvider
	proxies []C.Proxy
	version uint32
}

func (p *urlTestProvider) Proxies() []C.Proxy { return p.proxies }
func (p *urlTestProvider) Version() uint32    { return p.version }
func (p *urlTestProvider) Touch()             {}

func newURLTestForTest(provider *urlTestProvider, current C.Proxy, tolerance uint16) *URLTest {
	return &URLTest{
		GroupBase:  NewGroupBase(GroupBaseOption{Providers: []P.ProxyProvider{provider}}),
		fastNode:   current,
		tolerance:  tolerance,
		fastSingle: singledo.NewSingle[C.Proxy](time.Second),
	}
}

func TestURLTestTolerance(t *testing.T) {
	for _, tt := range []struct {
		name           string
		currentDelay   uint16
		candidateDelay uint16
		currentFirst   bool
		wantSwitch     bool
	}{
		{"first candidate within tolerance", 1000, 100, true, false},
		{"later candidate within tolerance", 1000, 100, false, false},
		{"at tolerance boundary", 1600, 100, false, false},
		{"above tolerance", 1601, 100, false, true},
		{"addition exceeds uint16", 65000, 64500, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			current := &urlTestProxy{name: "current", alive: true, delay: tt.currentDelay}
			candidate := &urlTestProxy{name: "candidate", alive: true, delay: tt.candidateDelay}
			proxies := []C.Proxy{candidate, current}
			if tt.currentFirst {
				proxies = []C.Proxy{current, candidate}
			}
			provider := &urlTestProvider{proxies: proxies, version: 1}
			want := current
			if tt.wantSwitch {
				want = candidate
			}
			if got := newURLTestForTest(provider, current, 1500).fast(false); got != want {
				t.Fatalf("selected %q, want %q", got.Name(), want.Name())
			}
		})
	}
}

func TestURLTestProviderReplacement(t *testing.T) {
	for _, currentFirst := range []bool{true, false} {
		name := "later candidate"
		if currentFirst {
			name = "first candidate"
		}
		t.Run(name, func(t *testing.T) {
			candidate := &urlTestProxy{name: "candidate", alive: true, delay: 100}
			old := &urlTestProxy{name: "current", alive: true, delay: 1000}
			provider := &urlTestProvider{proxies: []C.Proxy{candidate, old}, version: 1}
			group := newURLTestForTest(provider, old, 1500)
			if got := group.fast(false); got != old {
				t.Fatal("initial selection changed within tolerance")
			}

			current := &urlTestProxy{name: old.name, alive: true, delay: 1000}
			provider.proxies = []C.Proxy{candidate, current}
			if currentFirst {
				provider.proxies = []C.Proxy{current, candidate}
			}
			provider.version++
			group.fastSingle.Reset()
			if got := group.fast(false); got != current {
				t.Fatal("selection did not rebind to the replacement proxy")
			}

			// Health checks update the replacement, not the detached old proxy.
			current.alive = false
			group.fastSingle.Reset()
			if got := group.fast(false); got != candidate {
				t.Fatal("replacement failure did not trigger failover")
			}
		})
	}
}

func TestURLTestPendingProviderHealth(t *testing.T) {
	candidate := &urlTestProxy{name: "candidate", alive: true, delay: 100}
	old := &urlTestProxy{name: "current", alive: true, delay: 1000}
	// New proxies are alive before their first check, but have no delay history.
	current := &urlTestProxy{name: old.name, alive: true, delay: 0xffff}
	provider := &urlTestProvider{proxies: []C.Proxy{candidate, current}, version: 1}
	group := newURLTestForTest(provider, old, 1500)
	if got := group.fast(false); got != current {
		t.Fatal("pending check did not retain the replacement proxy")
	}
	// Also exercise subsequent selections before the first check completes.
	group.fastSingle.Reset()
	if got := group.fast(false); got != current {
		t.Fatal("pending check was treated as an excessive delay")
	}
	current.delay = 1000
	group.fastSingle.Reset()
	if got := group.fast(false); got != current {
		t.Fatal("completed healthy check ignored tolerance")
	}
	current.alive = false
	group.fastSingle.Reset()
	if got := group.fast(false); got != candidate {
		t.Fatal("completed failed check did not trigger failover")
	}
}

func TestURLTestRemovedProxy(t *testing.T) {
	candidate := &urlTestProxy{name: "candidate", alive: true, delay: 100}
	removed := &urlTestProxy{name: "removed", alive: true, delay: 1000}
	provider := &urlTestProvider{proxies: []C.Proxy{candidate}, version: 1}
	if got := newURLTestForTest(provider, removed, 1500).fast(false); got != candidate {
		t.Fatal("removed proxy remained selected")
	}
}
