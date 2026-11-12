package provider

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

// A provider starts its health check before it loads its proxies (baseProvider.Initial runs
// `go process()`, then Fetcher.Initial calls setProxies), and a subscription update replaces
// them while a round may be walking them. Run with -race: every round and every replacement
// here overlap.
func TestHealthCheckProxiesCanBeReplacedDuringARound(t *testing.T) {
	var proxies []C.Proxy
	for i := 0; i < 8; i++ {
		proxies = append(proxies, adapter.NewProxy(outbound.NewDirect()))
	}
	hc := NewHealthCheck(nil, "http://127.0.0.1:1/", 1, 300, true, nil)
	defer hc.close()

	replaced := make(chan struct{})
	go func() {
		defer close(replaced)
		for i := 0; i < 64; i++ {
			hc.setProxies(proxies[:i%len(proxies)+1])
		}
	}()
	for i := 0; i < 32; i++ {
		hc.check()
	}
	<-replaced
}
