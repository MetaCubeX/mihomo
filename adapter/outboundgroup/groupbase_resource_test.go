package outboundgroup

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type resourceNamedProxy struct {
	C.Proxy
	name string
}

func (p *resourceNamedProxy) Name() string { return p.name }
func resourceProxy(name string) C.Proxy {
	return &resourceNamedProxy{adapter.NewProxy(outbound.NewDirect()), name}
}

type resourceProvider struct {
	P.ProxyProvider
	mu      sync.RWMutex
	version uint32
	proxies []C.Proxy
	reads   atomic.Int64
	touches atomic.Int64
	onTouch func()
}

func (p *resourceProvider) Version() uint32 { p.mu.RLock(); defer p.mu.RUnlock(); return p.version }
func (p *resourceProvider) Proxies() []C.Proxy {
	p.reads.Add(1)
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.proxies
}
func (p *resourceProvider) Touch() {
	p.touches.Add(1)
	if p.onTouch != nil {
		p.onTouch()
	}
}
func (p *resourceProvider) VehicleType() P.VehicleType { return P.Inline }
func (p *resourceProvider) update(proxies []C.Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxies = proxies
	p.version++
}

func TestResourceGroupCacheHitAndInvalidation(t *testing.T) {
	a, b := resourceProxy("a"), resourceProxy("b")
	for _, n := range []int{1, 4, 32, 128} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			providers := make([]P.ProxyProvider, n)
			for i := range providers {
				providers[i] = &resourceProvider{version: 1, proxies: []C.Proxy{a}}
			}
			gb := NewGroupBase(GroupBaseOption{Providers: providers, EmptyFallback: b})
			first := gb.GetProxies(false)
			if len(first) != n {
				t.Fatal("initial membership", len(first))
			}
			for _, pd := range providers {
				p := pd.(*resourceProvider)
				p.onTouch = func() {
					if !gb.getProxiesMutex.TryLock() {
						t.Error("Touch called while holding group mutex")
					} else {
						gb.getProxiesMutex.Unlock()
					}
				}
			}
			hit := gb.GetProxies(true)
			if &hit[0] != &first[0] {
				t.Fatal("cache hit rebuilt result")
			}
			for _, pd := range providers {
				p := pd.(*resourceProvider)
				if p.reads.Load() != 1 || p.touches.Load() != 1 {
					t.Fatal("cache hit read/touch", p.reads.Load(), p.touches.Load())
				}
			}
			providers[n-1].(*resourceProvider).update([]C.Proxy{b})
			changed := gb.GetProxies(false)
			if len(changed) != n || changed[n-1] != b {
				t.Fatal("provider update not visible")
			}
			if gb.GetProxies(false)[n-1] != b {
				t.Fatal("updated cache not retained")
			}
		})
	}
}
func TestResourceGroupEmptyAndFilters(t *testing.T) {
	fallback := resourceProxy("fallback")
	p := &resourceProvider{version: 1}
	gb := NewGroupBase(GroupBaseOption{Providers: []P.ProxyProvider{p}, EmptyFallback: fallback})
	for i := 0; i < 2; i++ {
		got := gb.GetProxies(false)
		if len(got) != 1 || got[0] != fallback {
			t.Fatal("empty fallback changed")
		}
	}
	if p.reads.Load() != 2 {
		t.Fatal("empty result was cached")
	}
	p.update([]C.Proxy{resourceProxy("keep-a"), resourceProxy("drop"), resourceProxy("keep-b")})
	filtered := NewGroupBase(GroupBaseOption{Providers: []P.ProxyProvider{p}, Filter: "^keep", ExcludeFilter: "-b$", EmptyFallback: fallback})
	for i := 0; i < 2; i++ {
		got := filtered.GetProxies(false)
		if len(got) != 1 || got[0].Name() != "keep-a" {
			t.Fatal("filter/order changed")
		}
	}
	if got := NewGroupBase(GroupBaseOption{}).GetProxies(false); got != nil {
		t.Fatal("zero-provider behavior changed")
	}
}
func TestResourceGroupConcurrentUpdates(t *testing.T) {
	a, b := resourceProxy("a"), resourceProxy("b")
	p := &resourceProvider{version: 1, proxies: []C.Proxy{a}}
	gb := NewGroupBase(GroupBaseOption{Providers: []P.ProxyProvider{p}, EmptyFallback: a})
	gb.GetProxies(false)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				got := gb.GetProxies(j%2 == 0)
				if len(got) != 1 || (got[0] != a && got[0] != b) {
					t.Error("invalid snapshot")
					return
				}
			}
		}()
	}
	for j := 0; j < 500; j++ {
		if j%2 == 0 {
			p.update([]C.Proxy{b})
		} else {
			p.update([]C.Proxy{a})
		}
	}
	wg.Wait()
	p.update([]C.Proxy{b})
	if gb.GetProxies(false)[0] != b {
		t.Fatal("final generation not visible")
	}
}
func BenchmarkResourceGroupCacheHit(b *testing.B) {
	for _, n := range []int{1, 8, 32} {
		for _, touch := range []bool{false, true} {
			for _, parallel := range []bool{false, true} {
				b.Run(fmt.Sprintf("providers%d/touch%v/parallel%v", n, touch, parallel), func(b *testing.B) {
					proxy := resourceProxy("node")
					providers := make([]P.ProxyProvider, n)
					for i := range providers {
						hc := provider.NewHealthCheck([]C.Proxy{proxy}, "", 5000, 0, true, nil)
						pd, err := provider.NewCompatibleProvider(fmt.Sprint(i), []C.Proxy{proxy}, hc)
						if err != nil {
							b.Fatal(err)
						}
						b.Cleanup(func() { _ = pd.Close() })
						providers[i] = pd
					}
					gb := NewGroupBase(GroupBaseOption{Providers: providers, EmptyFallback: proxy})
					gb.GetProxies(false)
					b.ReportAllocs()
					b.ResetTimer()
					if parallel {
						b.RunParallel(func(pb *testing.PB) {
							for pb.Next() {
								if len(gb.GetProxies(touch)) != n {
									b.Error("membership changed")
									return
								}
							}
						})
					} else {
						for i := 0; i < b.N; i++ {
							if len(gb.GetProxies(touch)) != n {
								b.Fatal("membership changed")
							}
						}
					}
				})
			}
		}
	}
}

type resourceBlockingProvider struct {
	*resourceProvider
	entered, release chan struct{}
	once             sync.Once
}

func (p *resourceBlockingProvider) Proxies() []C.Proxy {
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return p.resourceProvider.Proxies()
}
func TestResourceGroupConcurrentColdCache(t *testing.T) {
	proxy := resourceProxy("node")
	pd := &resourceBlockingProvider{resourceProvider: &resourceProvider{version: 1, proxies: []C.Proxy{proxy}}, entered: make(chan struct{}), release: make(chan struct{})}
	gb := NewGroupBase(GroupBaseOption{Providers: []P.ProxyProvider{pd}, EmptyFallback: proxy})
	allTouched := make(chan struct{})
	touchRelease := make(chan struct{})
	var arrived atomic.Int64
	var release, releaseTouch sync.Once
	t.Cleanup(func() { releaseTouch.Do(func() { close(touchRelease) }); release.Do(func() { close(pd.release) }) })
	pd.onTouch = func() {
		if arrived.Add(1) == 32 {
			close(allTouched)
		}
		<-touchRelease
	}
	results := make(chan []C.Proxy, 32)
	for i := 0; i < 32; i++ {
		go func() { results <- gb.GetProxies(true) }()
	}
	select {
	case <-allTouched:
	case <-time.After(5 * time.Second):
		t.Fatal("cold readers did not reach Touch barrier")
	}
	releaseTouch.Do(func() { close(touchRelease) })
	select {
	case <-pd.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("cold builder did not start")
	}
	release.Do(func() { close(pd.release) })
	var first []C.Proxy
	for i := 0; i < 32; i++ {
		var got []C.Proxy
		select {
		case got = <-results:
		case <-time.After(5 * time.Second):
			t.Fatal("cold reader did not finish")
		}
		if len(got) != 1 || got[0] != proxy {
			t.Fatal("partial cold cache published")
		}
		if first == nil {
			first = got
		} else if &first[0] != &got[0] {
			t.Fatal("concurrent miss rebuilt an already published generation")
		}
	}
	if pd.reads.Load() != 1 {
		t.Fatal("duplicate cold rebuild", pd.reads.Load())
	}
}
