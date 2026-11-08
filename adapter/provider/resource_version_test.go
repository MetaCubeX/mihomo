package provider

import (
	"fmt"
	C "github.com/metacubex/mihomo/constant"
	"math"
	"sync"
	"testing"
)

func TestResourceProviderVersionPublication(t *testing.T) {
	bp := &baseProvider{healthCheck: &HealthCheck{}}
	if bp.Version() != 0 {
		t.Fatal("initial version")
	}
	bp.setProxies([]C.Proxy{nil})
	if bp.Version() != 1 || len(bp.Proxies()) != 1 || len(bp.healthCheck.proxies) != 1 {
		t.Fatal("incomplete published update")
	}
	const updates = 1000
	done := make(chan struct{})
	errs := make(chan error, 8)
	var ready, readers sync.WaitGroup
	ready.Add(8)
	readers.Add(8)
	for i := 0; i < 8; i++ {
		go func() {
			defer readers.Done()
			last := bp.Version()
			ready.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				version := bp.Version()
				if version < last || version > updates+1 {
					errs <- fmt.Errorf("invalid version progression: %d -> %d", last, version)
					return
				}
				last = version
				if len(bp.Proxies()) > 1 {
					errs <- fmt.Errorf("invalid proxy snapshot")
					return
				}
			}
		}()
	}
	ready.Wait()
	for i := 0; i < updates; i++ {
		if i%2 == 0 {
			bp.setProxies(nil)
		} else {
			bp.setProxies([]C.Proxy{nil})
		}
	}
	close(done)
	readers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if bp.Version() != updates+1 || len(bp.Proxies()) != 1 {
		t.Fatal("final update missing")
	}
}
func TestResourceProviderVersionWrap(t *testing.T) {
	bp := &baseProvider{healthCheck: &HealthCheck{}}
	bp.version.Store(math.MaxUint32)
	bp.setProxies(nil)
	if bp.Version() != 0 {
		t.Fatal("uint32 wrap changed")
	}
}
